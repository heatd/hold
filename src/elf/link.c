/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <fnv.h>
#include <elf/ar.h>
#include <elf/elf.h>
#include <elf/output_section.h>

#if defined(__linux__) || defined(__onyx__)
#define HOLD_ELF_PLATFORM 1
#else
#error "Platform not ELF!"
#endif

#ifdef HOLD_ELF_PLATFORM
#define HOLD_ELF_BITNESS (__CHAR_BIT__ * __SIZEOF_LONG__) 
#endif

static struct symbol_table table;
static struct input_file **files;
static unsigned int nfilescap;
static unsigned int nfiles;

static
const char *elf_get_str(u32 str, const char *strs)
{
        return strs + str;
}

static
void replace_sym(struct symbol *dst, struct symbol *src)
{
        src->next = dst->next;
        free((void *) dst->name);
        memcpy(dst, src, sizeof(*src));
        src->nofree_name = 1;

}

static
int resolve_sym_conflict(struct symbol *s, struct symbol *sym)
{
        /* Rules for symbol "overlaying":
         * UNDEFINED -> DEFINED is allowed (we have just defined a symbol, yay!)
         * DEFINED weak -> DEFINED strong is allowed
         * DEFINED -> DEFINED is an error
         * UNDEFINED -> UNDEFINED is a nop
         * DEFINED -> UNDEFINED is a nop
         * LAZY -> LAZY is a nop (second symbol is ignored, see below for details on static archives)
         * DEFINED -> LAZY is a nop
         * UNDEFINED -> LAZY and LAZY -> UNDEFINED prompt the archive
         *              file to be loaded
         */
        switch (s->symtype) {
                case SYM_TYPE_DEFINED: {
                        if (sym->symtype == SYM_TYPE_DEFINED) {
                                if (!(s->weak && !sym->weak) && !(!s->weak && sym->weak)) {
                                        warnx("double definition error for symbol %s", sym->name);
                                        return -1;
                                }

                                if (!sym->weak) {
                                        /* ok, previous was weak, new is strong, replace. */
                                        replace_sym(s, sym);
                                }

                                /* fallthrough to return 0 */
                         }

                         return 0;
                }

                case SYM_TYPE_UNDEFINED: {
                        if (sym->symtype == SYM_TYPE_DEFINED) {
                                replace_sym(s, sym);
                                return 0;
                        }

                        if (sym->symtype == SYM_TYPE_LAZY)
                                return resolve_lazy(sym);
                        return 0;
                }

                case SYM_TYPE_LAZY: {
                        /* Notes on static archive symbol resolution:
                         * Traditionally, static library symbol resolution is
                         * very simple. Imagining an invocation such as
                         * "ld a.o b.o libc.a c.o", libc.a will resolve a.o
                         * and b.o's undefined references, but not c.o's.
                         * When looking up a symbol, we only look at the first
                         * entry in that archive's symbol table; it doesn't
                         * matter whether the entry is weak or strong or whatnot.
                         * We take a slightly different strategy: lld does not
                         * do this, and "ld libc.a a.o b.o c.o" will resolve a,
                         * b and c's undefined references. This allows for
                         * greater parallelism when linking.
                         *
                         * Note: a common trick in static libraries such as
                         * libc.a is to stub out certain functions with weak
                         * binding, in order to avoid pulling in more object
                         * files. If those individual features are then pulled
                         * (through, say, a reference to a symbol), it will pull
                         * the entire object file, replacing the previous weak
                         * symbol with a strong one.
                         *
                         * It's always worth keeping in mind that a single
                         * symbol reference pulls an entire object file.
                         */
                        if (sym->symtype == SYM_TYPE_LAZY) {
                                return 0;
                        }

                        if (sym->symtype == SYM_TYPE_UNDEFINED)
                                return resolve_lazy(s);

                        replace_sym(s, sym);
                        return 0;
                }

                default:
                        abort();
        }
}

int add_to_symtable(struct symbol *sym)
{
        /* Add @sym to the symbol table. If we overlay this symbol on top of another,
         * make sure to memcpy ourselves over, so existing references refer to the same symbol.
         */
        u32 index = sym->name_hash & (SYMBOL_TABLE_SIZE - 1);
        struct symbol **sp = &table.buckets[index];

        /* Make sure all symbols added are correctly filled, and that no local
         * symbol makes it to the global symbol tables.
         */
        assert(sym->name);
        assert(sym->local == 0);
        assert(strlen(sym->name) > 0);

        while (*sp) {
                struct symbol *s = *sp;
                /* Check for name collisions */
                if (s->name_hash == sym->name_hash && !strcmp(s->name, sym->name)) {
                        if (resolve_sym_conflict(s, sym) < 0)
                                return -1;
                        /* We'll never append after having a conflict. Either
                         * resolve_sym_conflict overwrote it with memcpy, or
                         * we got an error. No other option.
                         */
                        return 0;
                }

                sp = &(s->next);
        }

        *sp = sym;
        return 0;
}

struct symbol *lookup_symtable(const char *name)
{
        fnv_hash_t hash = fnv_hash(name, strlen(name));
        u32 index = hash & (SYMBOL_TABLE_SIZE - 1);
        struct symbol *s = table.buckets[index];

        while (s) {
                if (s->name_hash == hash && !strcmp(s->name, name))
                        return s;
                s = s->next;
        }

        return NULL;
}

static
void relocate_sym(struct symbol *s)
{
        struct input_section *inp;
        struct output_section *os;

        /* Skip ABS, lazy symbols and weak undefined */
        if (s->abs || s->symtype == SYM_TYPE_LAZY || (s->weak && s->symtype == SYM_TYPE_UNDEFINED))
                return;

        inp = s->section;
        assert(inp != NULL);
        os = inp->out;
        assert(os != NULL);

        verbose("Relocating symbol %s from %lx to %lx\n", s->name, s->value,
                s->value + os->address + inp->output_off);

        s->value += os->address + inp->output_off;
}

void relocate_symbols(void)
{
        u32 i, j;

        /* Relocate:
         *  - Symbols in the symbol table
         *  - STB_LOCAL symbols in the input file symbol tables
         */
        for (i = 0; i < SYMBOL_TABLE_SIZE; i++) {
                struct symbol *s;
                for (s = table.buckets[i]; s != NULL; s = s->next)
                        relocate_sym(s);
        }

        for (i = 0; i < nfiles; i++) {
                struct input_file *inp = files[i];
                verbose("Relocating %s\n", inp->name);

                for (j = 0; j < inp->nsyms; j++) {
                        struct symbol *s = &inp->syms[j];
                        if (s->local)
                                relocate_sym(s);
                }
        }
}

static
int check_for_unresolved_syms(void)
{
        int i;
        int st = 0;

        for (i = 0; i < SYMBOL_TABLE_SIZE; i++) {
                struct symbol *s = table.buckets[i];

                while (s) {
                        if (s->symtype == SYM_TYPE_UNDEFINED) {
                                if (s->weak) {
                                        /* A weak undefined reference is
                                         * allowed. In this case, we set value
                                         * to 0.
                                         */
                                        s->value = 0;
                                } else {
                                        warnx("Undefined symbol %s", s->name);
                                        st = -1;
                                }
                        }

                        s = s->next;
                }
        }

        return st;
}

static
int process_elf_symbols(struct input_file *file, elf_shdr *symtab,
                        elf_shdr *strtab, u8 *mapping)
{
        const char *strs = (const char *) mapping + strtab->sh_offset;
        elf_sym *sym = (elf_sym *) (mapping + symtab->sh_offset);
        u32 nsyms = symtab->sh_size / symtab->sh_entsize;
        u32 i;

        /* Note that we discard the first entry (UND) */
        file->syms = calloc(nsyms - 1, sizeof(struct symbol));
        if (!file->syms) {
                warn("process_elf_symbols: calloc");
                return -1;
        }

        file->nsyms = nsyms - 1;

        for (i = 0; i < nsyms; i++, sym =
                (elf_sym *)(((u8 *) sym) + symtab->sh_entsize)) {
                if (i == 0) {
                        /* Skip UND */
                        continue;
                }

                const char *symname = elf_get_str(sym->st_name, strs);
                struct symbol *symbol = &file->syms[i - 1];

                symbol->name = strdup(symname);
                if (!symbol->name) {
                        warn("strdup");
                        return -1;
                }

                symbol->name_hash = fnv_hash(symname, strlen(symname));
                symbol->size = sym->st_size;
                symbol->st_type = ELF64_ST_TYPE(sym->st_info);
                symbol->st_vis = ELF64_ST_VISIBILITY(sym->st_info);
                symbol->value = sym->st_value;

                if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL)
                        symbol->local = 1;
                else if (ELF64_ST_BIND(sym->st_info) == STB_WEAK)
                        symbol->weak = 1;

                symbol->symtype = SYM_TYPE_DEFINED;

                if (sym->st_shndx == SHN_ABS) {
                        /* Absolute symbol, should not be affected by relocation. */
                        symbol->abs = 1;
                } else if (sym->st_shndx == SHN_UNDEF) {
                        symbol->symtype = SYM_TYPE_UNDEFINED;
                } else {
                        symbol->section = &file->sections[sym->st_shndx - 1];
                        if (ELF64_ST_TYPE(sym->st_info) == STT_SECTION) {
                                /* Treat the section's name as the symbol's name */
                                free((void *) symbol->name);
                                symbol->name = symbol->section->name;
                                symbol->name_hash = fnv_hash(symbol->name, strlen(symbol->name));
                                symbol->nofree_name = 1;
                        }
                }

                verbose("symbol: %s\n", symbol->name);

                if (!symbol->local) {
                        if (add_to_symtable(symbol) < 0)
                                return -1;
                }
        }

        return 0;
}

static
uptr get_fd_size(int fd)
{
        struct stat buf;
        if (fstat(fd, &buf) < 0)
                err(1, "fstat");
        return buf.st_size;
}

static
int default_file_open(struct input_file *file)
{
        file->openf.fd = open(file->name, O_RDONLY);
        if (file->openf.fd < 0) {
                err(1, "%s", file->name);
        }

        return 0;
}

static
void default_file_read(struct input_file *file, void *buf, uptr size, uptr offset)
{
        if (pread(file->openf.fd, buf, size, offset) < 0) {
                err(1, "default_file_read: pread");
        }
}

static void default_file_close(struct input_file *file)
{
        close(file->openf.fd);
}

const struct input_file_ops default_ops =
{
        .open = default_file_open,
        .read = default_file_read,
        .close = default_file_close
};

static
struct input_file *create_input_file(const char *filename)
{
        struct input_file *file = calloc(1, sizeof(struct input_file));
        if (!file)
                return NULL;
        file->name = filename;

        if (nfilescap < nfiles + 1) {
                nfilescap = nfilescap > 0 ? nfilescap << 1 : 16;
                files = reallocarray(files, nfilescap, sizeof(struct input_file *));
                if (!files)
                        return NULL;
        }

        file->openf.fd = -1;
        file->ops = &default_ops;

        files[nfiles++] = file;
        return file;
}

static
int parse_elf_sections(struct input_file *f, uptr shoff, u32 shnum, u32 shentsize, u8 *mapping)
{
        elf_shdr *strtab, *symtab;
        elf_ehdr *ehdr = (elf_ehdr *) mapping;
        elf_shdr *section = (elf_shdr *) (mapping + shoff);
        elf_shdr *shstrtab = (elf_shdr *) (mapping + shoff + ehdr->e_shstrndx * shentsize);
        const char *shstrs = (const char *) mapping + shstrtab->sh_offset;
        u32 i;

        f->nsections = shnum - 1;
        f->sections = calloc(shnum - 1, sizeof(struct input_section));
        if (!f->sections) {
                warn("Failed to allocate input sections");
                return -1;
        }

        strtab = symtab = NULL;

        for (i = 0; i < shnum; i++, section = (elf_shdr *)((u8 *) section + shentsize)) {
                const char *name;
                struct input_section *sec;

                if (i == 0) {
                        /* Skip the NULL section */
                        continue;
                }

                name = elf_get_str(section->sh_name, shstrs);
                sec = &f->sections[i - 1];

                sec->file = f;
                sec->name = strdup(name);
                if (!sec->name) {
                        warn("strdup");
                        return -1;
                }

                sec->sh_flags = section->sh_flags;
                sec->sh_type = section->sh_type;
                sec->sh_addralign = section->sh_addralign;
                sec->sh_offset = section->sh_offset;
                sec->sh_size = section->sh_size;

                /* Save relevant tables */
                if (!strcmp(name, ".strtab")) {
                        strtab = section;
                } else if (!strcmp(name, ".symtab")) {
                        symtab = section;
                }

                verbose("processing section %s(%s)\n", sec->name, f->name);
                verbose("section size: %lu bytes\n", section->sh_size);
        }

        int st = process_elf_symbols(f, symtab, strtab, mapping);
        if (st < 0)
                return st;

        /* After symbols, process relocations */
        section = (void *) (mapping + shoff);
        for (i = 0; i < shnum; i++, section = (void *)((u8 *) section + shentsize)) {
                if (section->sh_type == SHT_RELA) {
                        verbose("%s: Processing SHT_RELA (%s)\n", f->name,
                                elf_get_str(section->sh_name, shstrs));
                        if (process_rela(f, section, mapping) < 0) {
                                return -1;
                        }
                }
        }
        return 0;
}

static
int parse_elf(struct input_file *f, u8 *mapping, uptr filesz)
{
        elf_ehdr *header = (elf_ehdr *) mapping;
        if (!!memcmp(header->e_ident, "\x7f""ELF", 4)) {
                if (is_ar_archive(mapping))
                        return parse_ar(f, mapping, filesz);
                warnx("%s is not an ELF file!", f->name);
                return -1;
        }

        f->emachine = header->e_machine;

        /* XXX this is a hack */
        if (f->emachine != EM_X86_64) {
                warnx("%s is not made for the current machine (e_machine = %x)", f->name, f->emachine);
                return -1;
        }

        /* TODO: Check other things in the ehdr */

        if (parse_elf_sections(f, header->e_shoff, header->e_shnum,
                               header->e_shentsize, mapping) < 0) {
                return -1;
        }

        return 0;
}

int elf_process_objfile(const char *filename, void *map, uptr fd_size,
                        const struct input_file_ops *ops, int flags)
{
        struct input_file *f = create_input_file(filename);
        if (!f) {
                warn("%s: Failed to create input_file", filename);
                return -1;
        }

        f->ops = ops;

        if (ops != &default_ops) {
                /* HACK! I hate this, but since we only have 3 types of
                 * input files atm (object/archive file and .o coming from a .a)
                 * this solution Just Works.
                 */
                f->ardata = map;
        }

        if (flags & ELF_PROCESS_FILENAME_FREE)
                f->free_name = 1;

        return parse_elf(f, map, fd_size);
}

static
int elf_process_input(const char *filename)
{
        uptr fd_size;

        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
                warn("%s: Error opening", filename);
                return -1;
        }

        fd_size = get_fd_size(fd);

        void *map = mmap(NULL, fd_size, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) {
                warn("%s: Error mmapping input file", filename);
                return -1;
        }

        int st = elf_process_objfile(filename, map, fd_size, &default_ops, 0);       
        if (!is_ar_archive(map)) {
                /* HACK! Since ar archives want permanent mappings, this works.
                 * But should eventually be refactored as something else.
                 */
#define DEBUG_MMAP 1
#ifdef DEBUG_MMAP
                /* Catch erroneous accesses to the file mappings using PROT_NONE */
                mprotect(map, fd_size, PROT_NONE);
#else
                munmap(map, get_fd_size(fd));
#endif
        }

        close(fd);
        return st;
}

static void destroy_input_files(void);
static void destroy_symbol_table(void);

int elf_do_link(struct hold_options *options)
{
        struct output_section **out_sec;
        u32 nr_output_sec;
        int i;

        for (i = 0; i < options->ninput_files; i++) {
                const char *input = options->input_files[i];
                if (elf_process_input(input) < 0)
                        return 1;
        }

        if (check_for_unresolved_syms() < 0)
                return 1;

        out_sec = elf_merge_sections(files, nfiles, &nr_output_sec);
        if (!out_sec)
                return 1;

        struct elf_writer writer;
        memset(&writer, 0, sizeof(writer));
        writer.files = files;
        writer.nfiles = nfiles;
        writer.options = options;
        writer.out_section = out_sec;
        writer.nr_output_secs = nr_output_sec;

        int st = elf_do_write(&writer);

#ifdef HOLD_ASAN_ENABLED
        elf_writer_destroy(&writer);
        destroy_symbol_table();
        destroy_input_files();
#endif
        return st;
}

static
void destroy_symbol_table(void)
{
}

static
void destroy_file(struct input_file *inp)
{
        u32 i;

        free(inp->relocs);

        for (i = 0; i < inp->nsections; i++) {
                struct input_section *sec = &inp->sections[i];
                free((void *) sec->name);
        }

        free(inp->sections);

        for (i = 0; i < inp->nsyms; i++) {
                struct symbol *s = &inp->syms[i];
                if (!s->nofree_name)
                        free((void *) s->name);
        }

        free(inp->syms);

        if (inp->free_name)
                free((void *) inp->name);

        free(inp);
}

static
void destroy_input_files(void)
{
        u32 i;

        for (i = 0; i < nfiles; i++) {
                struct input_file *inp = files[i];
                destroy_file(inp);
        }
}
