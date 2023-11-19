/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <elf.h>
#include <err.h>
#include <stdio.h>
#include <hold.h>

#include <elf/elf.h>
#include <elf/output_section.h>

static
void do_reloc(struct relocation *reloc, struct input_section *inp, u8 *mapping)
{
        /* Note: Uppercase, single letter variable names follow the notation used
         * in the AMD64 ABI.
         */

        muptr S = reloc->sym->value;
        s64 A = reloc->addend;

        struct output_section *out = inp->out;
        muptr offset = out->offset + inp->output_off + reloc->offset;
        muptr P = out->address + inp->output_off + reloc->offset;
        u64 *p = (u64 *) (mapping + offset);
        u32 *p32 = (u32 *) (mapping + offset);
        u16 *p16 = (u16 *) p32;
        u8 *p8 = (u8 *) p16;

#define REL64(val) *p = (val)
#define REL32(val) *p32 = (val)

        switch(reloc->rel_type)
        {
                case R_X86_64_PC32:
                /* Note: We can relax PLT32 into PC32 if the function is defined in this binary */
                case R_X86_64_PLT32:
                        REL32(S + A - P);
                        break;
                case R_X86_64_32:
                case R_X86_64_32S:
                        REL32(S + A);
                        break;
                case R_X86_64_64:
                        REL64(S + A);
                        break;
                case R_X86_64_16:
                        *p16 = S + A;
                        break;
                case R_X86_64_PC16:
                        *p16 = S + A - P;
                        break;
                case R_X86_64_8:
                        *p8 = S + A;
                        break;
                case R_X86_64_PC8:
                        *p8 = S + A - P;
                        break;
                default:
                        errx(1, "Unhandled relocation type %x\n", reloc->rel_type);
        }
}

void elf_do_relocs(struct input_file *file, struct relocation *relocs, u32 nrelocs, u8 *mapping)
{
        u32 i;

        for (i = 0; i < nrelocs; i++) {
                struct input_section *section = &file->sections[relocs[i].section];
                /* HACK: Let's only handle sections that have been mapped in the binary.
                 * At the moment, SHF_ALLOC.
                 */
                if (section->out && section->out->offset)
                        do_reloc(&relocs[i], section, mapping);
        }
}
