/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#ifndef HOLD_ELF_ELF_H
#define HOLD_ELF_ELF_H

#include <elf.h>

#include <hold.h>

enum symbol_type {
        SYM_TYPE_DEFINED = 0,
        SYM_TYPE_UNDEFINED,
        SYM_TYPE_LAZY, /* for LLVM-style archive handling */
};

/* Define 64-bit as the max uptr */
typedef uint64_t muptr;

struct input_section;

struct symbol {
        const char *name;
        u32 name_hash;
        enum symbol_type symtype;
        muptr value;
        muptr size;

        /* See ElfN_Sym's st_info and STT_* */
        u8 st_type : 4;
        /* .. and STV_* */
        u8 st_vis : 3;
        u8 weak : 1;
        u8 local : 1;
        u8 abs : 1;
        /* names are only owned by the symbol table of the input_file.
         * If we want to free a name, we must only free it if this is
         * has not been an overridden symbol.
         */
        u8 nofree_name : 1;

        /* For lazy symbols, this holds the position in the ar archive */
        u32 ar_pos;
        union {
                struct input_section *section;
                struct input_file *file;
        };

        struct symbol *next;
};

#define SYMBOL_TABLE_SIZE 128
struct symbol_table {
        struct symbol *buckets[SYMBOL_TABLE_SIZE];
};

struct relocation {
        struct symbol *sym;
        muptr offset;
        s64 addend;
        u32 section;
        u16 rel_type;
};

/* Set when the section should be ignored by the final link.
 * Used on symtab, strtab and shstrtab, which are synthesized
 * by the linker itself.
 */
#define INPUT_SECTION_NOLINK (1 << 0)

struct input_file;
struct output_section;

struct input_section {
        const char *name;
        struct input_file *file;
        struct output_section *out;
        /* Next input section in the output section */
        struct input_section *next_outputsec;
        /* XXX sh_flags is not 32-bit for Elf64, but all flags seem to fit in
         * 32-bits.
         */
        u32 sh_flags;
        u32 sh_type;
        muptr sh_addralign;
        muptr sh_size;
        muptr sh_offset;
        muptr output_off;
};

struct ar_archive_data;

struct input_file_ops {
        int (*open)(struct input_file *file);
        void (*read)(struct input_file *file, void *buf, uptr size, uptr offset);
        void (*close)(struct input_file *file);
};

struct input_file {
        const char *name;
        u16 emachine;
        u32 free_name : 1;

        struct input_section *sections;
        u32 nsections;
        struct symbol *syms;
        u32 nsyms;
        struct relocation *relocs;
        u32 nrelocs;

        struct ar_archive_data *ardata;

        struct {
                u8 *long_file_names;
        } archive;

        union {
                int fd;
                struct {
                        uptr archive_off;
                };
        } openf;

        const struct input_file_ops *ops;
};

typedef Elf64_Ehdr elf_ehdr;
typedef Elf64_Shdr elf_shdr;
typedef Elf64_Sym elf_sym;
typedef Elf64_Rela elf_rela;
typedef Elf64_Phdr elf_phdr;

int process_rela(struct input_file *file, elf_shdr *section, u8 *mapping);
struct symbol *lookup_symtable(const char *name);

struct output_section **elf_merge_sections(struct input_file **files, u32 nfiles,
                                          u32 *p_noutput);

struct program_header;

struct elf_writer {
        struct output_section **out_section;
        u32 nr_output_secs;
        struct hold_options *options;
        struct input_file **files;
        u32 nfiles;
        struct program_header *phdr;
        u32 nr_phdrs;
};

/* Taking an elf writer, write an output, linked and relocated ELF file */
int elf_do_write(struct elf_writer *writer);

void elf_writer_destroy(struct elf_writer *writer);

void relocate_symbols(void);

void elf_do_relocs(struct input_file *file, struct relocation *relocs, u32 nrelocs, u8 *mapping);

int add_to_symtable(struct symbol *sym);

/* If set, we should free this filename (as it was malloc'd) */
#define ELF_PROCESS_FILENAME_FREE (1 << 0)

int elf_process_objfile(const char *filename, void *map, uptr fd_size,
                        const struct input_file_ops *ops, int flags);

#endif
