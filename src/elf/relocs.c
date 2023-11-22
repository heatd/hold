/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <assert.h>
#include <elf.h>
#include <err.h>
#include <hold.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <elf/elf.h>

int process_rela(struct input_file *file, elf_shdr *section, u8 *mapping)
{
        /* For REL and RELA, the target section's index is stored in sh_info */
        u32 target_section = section->sh_info - 1;
        elf_rela *rela = (elf_rela *) (mapping + section->sh_offset);
        uptr nr_relocs = section->sh_size / section->sh_entsize;
        uptr i = file->nrelocs;

        file->nrelocs += nr_relocs;
        file->relocs = reallocarray(file->relocs, file->nrelocs, sizeof(struct relocation));
        if (!file->relocs) {
                warn("calloc");
                return -1;
        }

        memset(file->relocs + i, 0, sizeof(struct relocation) * nr_relocs);

        for (; i < file->nrelocs; i++, rela = (elf_rela *)((u8 *) rela + section->sh_entsize)) {
                struct relocation *reloc = &file->relocs[i];
                u32 target_sym_idx;

                reloc->offset = rela->r_offset;
                reloc->rel_type = ELF64_R_TYPE(rela->r_info);
                reloc->addend = rela->r_addend;
                reloc->section = target_section;

                target_sym_idx = ELF64_R_SYM(rela->r_info);

                if (target_sym_idx != STN_UNDEF) {
                        struct symbol *sym = &file->syms[target_sym_idx - 1];
                        if (!sym->local) {
                                /* If this is not a local symbol, we have a
                                 * symbol table entry, so look that up.
                                 */
                                sym = lookup_symtable(sym->name);
                        }

                        assert(sym != NULL);

                        reloc->sym = sym;
                }

                verbose("Relocation %x (offset %lx, %s+%lx)\n", reloc->rel_type, reloc->offset,
                        reloc->sym ? reloc->sym->name : "0", reloc->addend);
        }

        return 0;
}

