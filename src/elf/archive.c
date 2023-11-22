/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>

#include <fnv.h>

#include <elf/ar.h>
#include <elf/elf.h>

static
int parse_ar_symtab(struct input_file *file, const struct ar_hdr *hdr, u64 size)
{
        const char *string_data;
        u32 *data, syms, i;
        /* Look at the symbol table and add lazy symbols
         * Note that the symbol table is always the first entry.
         */

        /* The symbol table is defined by:
         *        [Number of entries in the table (big endian)]
         *        [  N entries (big endian) for the position within the ar ]
         *        [  N zero-terminated strings (symbol names) in the same order as above  ]
         */
        data = (u32 *) (hdr + 1);
        syms = be32toh(*data);
        string_data = (const char *) (data + syms + 1);
        verbose("%s: Found %u symbols\n", file->name, syms);
        file->syms = calloc(syms, sizeof(struct symbol));
        if (!file->syms)
                return -1;
        file->nsyms = syms;

        for (i = 0; i < syms; i++) {
                struct symbol *sym = &file->syms[i];
                const char *name;
                u32 pos;
                uptr namelen;

                pos = be32toh(data[i + 1]);
                name = string_data;
                namelen = strlen(name);
                string_data += namelen + 1;

                sym->name = strdup(name);
                if (!sym->name)
                        return -1;
                sym->name_hash = fnv_hash(sym->name,  namelen);
                sym->symtype = SYM_TYPE_LAZY;
                sym->ar_pos = pos;
                sym->file = file;

                if (add_to_symtable(sym) < 0)
                        return -1;
        }

        return 0;
}

int parse_ar(struct input_file *file, const void *mapping, unsigned long filesz)
{
        const struct ar_hdr *hdr = mapping + strlen(AR_MAGIC);
        const u8 *end = mapping + filesz;
        int seen_symtab = 0, seen_lfn = 0;

        if (!!memcmp(hdr->ar_fmag, ARFMAG, 2)) {
                warn("%s looked like an AR archive, but it isn't!", file->name);
                return -1;
        }

        while ((u8 *) hdr < end) {
                u64 size;

                if (seen_symtab && seen_lfn) {
                        /* We're only here for the symtab (first entry) and
                         * the LFN entry (probably the second entry). Anything
                         * else is irrelevant to us atm.
                         */
                        break;
                }
                sscanf(hdr->ar_size, "%10lu", &size);

                if (hdr->ar_name[0] == '/') {
                        /* Check what kind of special entry this is */
                        switch(hdr->ar_name[1]) {
                                case ' ': {
                                        /* symbol table */
                                        if (parse_ar_symtab(file, hdr, size) < 0)
                                                return 1;
                                        seen_symtab++;
                                        break;
                                }

                                case '/': {
                                        /* Long filename entry */
                                        file->archive.long_file_names = (u8 *) (hdr + 1);
                                        seen_lfn++;
                                        break;
                                }
                        }
                }

                if (size & 1)
                        size++;
                hdr = (struct ar_hdr *) ((u8 *) (hdr + 1) + size);
        }


        file->ardata = (struct ar_archive_data *) mapping;

        return 0;
}

static
int archive_obj_open(struct input_file *file)
{
        return 0;
}

static
void archive_obj_read(struct input_file *file, void *buf, uptr size, uptr offset)
{
        u8 *mapping = (u8 *) file->ardata;
        memcpy(buf, mapping + offset, size);
}

static
void archive_obj_close(struct input_file *file)
{
        /* nop */
}

const struct input_file_ops ar_objfile_ops =
{
        .open = archive_obj_open,
        .read = archive_obj_read,
        .close = archive_obj_close
};

static
char *ar_get_name(struct input_file *file, struct ar_hdr *hdr)
{
        int i;
        char buf[sizeof(hdr->ar_name) + 1];

        if (hdr->ar_name[0] == '/') {
                /* Long filename (this is 100% not going to be a symbol table
                 * or LFN entry).
                 */
                char *lfn_start, *lfn_end, *str;
                uptr offset;
                if (sscanf(hdr->ar_name + 1, "%15lu", &offset) != 1) {
                        warn("ar_get_name: sscanf");
                        return NULL;
                }

                lfn_start = (char *) file->archive.long_file_names + offset;
                lfn_end = strchr(lfn_start, '/');
                str = calloc(lfn_end - lfn_start + 1, 1);
                if (!str)
                        return NULL;
                memcpy(str, lfn_start, lfn_end - lfn_start);
                return str;
        }

        for (i = 0; i < sizeof(hdr->ar_name); i++) {
                char c;

                c = hdr->ar_name[i];

                if (c == '/') {
                        buf[i] = 0;
                        break;
                }

                buf[i] = c;
        }

        return strdup(buf);
}

struct deferred_sym {
        struct symbol *s;
        struct deferred_sym *next_defer;
};

static
struct deferred_sym *defer_head, *defer_tail;

static int in_resolve_lazy = 0;

static
int defer_sym(struct symbol *sym)
{
        /* Because resolve_lazy can pull in extra object files, we may get
         * stuck in boundless stack recursion. To avoid that, defer symbols
         * in a list that we'll look at after resolve_lazy is complete.
         */
        struct deferred_sym *df;

        df = malloc(sizeof(*df));
        if (!df)
                return -1;
        df->s = sym;
        df->next_defer = NULL;

        if (!defer_head)
                defer_head = df;
        else
                defer_tail->next_defer = df;
        defer_tail = df;
        return 0;
}

static
int resolve_lazy_internal(struct symbol *sym)
{
        u8 *mapping = (u8 *) sym->file->ardata;
        struct ar_hdr *hdr = (struct ar_hdr *) (mapping + sym->ar_pos);
        char buf[sizeof(hdr->ar_size) + 1];
        char *filename;
        uptr size;
        printf("%s\n", sym->file->name);

        memcpy(buf, hdr->ar_size, sizeof(hdr->ar_size));
        buf[sizeof(hdr->ar_size)] = 0;

        if (sscanf(buf, "%lu", &size) != 1) {
                warn("sscanf");
                return -1;
        }

        filename = ar_get_name(sym->file, hdr);
        if (!filename)
                return -1;

        int st = elf_process_objfile(filename, hdr + 1, size, &ar_objfile_ops,
                                     ELF_PROCESS_FILENAME_FREE);

        if (st < 0) {
                free(filename);
                return -1;
        }

        return st;
}

static
int undefer_syms(void)
{
        while (defer_head) {
                /* We need to be careful to avoid list corruption. Lets splice
                 * the list every time we check it is not empty.
                 */
                struct deferred_sym *head, *next;

                head = defer_head;
                defer_head = defer_tail = NULL;

                while (head != NULL) {
                        struct symbol *sym = head->s;
                        next = head->next_defer;
                        free(head);

                        if (sym->symtype != SYM_TYPE_LAZY) {
                                /* Something unlazied it in the meanwhile, just
                                 * skip.
                                 */
                                head = next;
                                continue;
                        }

                        if (resolve_lazy_internal(sym) < 0) {
                                in_resolve_lazy = 0;
                                return -1;
                        }

                        head = next;
                }
        }

        in_resolve_lazy = 0;
        return 0;
}

int resolve_lazy(struct symbol *sym)
{
        int st;
        assert(sym->symtype == SYM_TYPE_LAZY);

        if (in_resolve_lazy)
                return defer_sym(sym);

        in_resolve_lazy = 1;
        st = resolve_lazy_internal(sym);

        if (st < 0) {
                in_resolve_lazy = 0;
                return st;
        }

        return undefer_syms();
}
