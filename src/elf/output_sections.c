/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <hold.h>
#include <elf/elf.h>
#include <elf/output_section.h>

static
int try_merge(struct output_section *out, u32 nr_output, struct input_section *inp)
{
        u32 i;

        /* TODO: In reality, this is probably not so simple... */
        for (i = 0; i < nr_output; i++, out++) {
                if (!strcmp(out->name, inp->name))
                        goto merge;
        }

        return -1;
merge:
        verbose("Merging input section %s(%s) into output section %s\n", inp->name,
                inp->file->name, out->name);
        out->max_alignment = out->max_alignment > inp->sh_addralign ? out->max_alignment : inp->sh_addralign;
        assert(out->isection_head != NULL);
        assert(out->isection_tail != NULL);

        struct input_section *tail = out->isection_tail;
        if (inp->sh_addralign > 1) {
                /* Align size so we can insert the new section at tail
                 * Note that sh_addralign is always a power of 2.
                 */
                out->size = (out->size + inp->sh_addralign - 1) & -inp->sh_addralign;
        }
        out->size += inp->sh_size;

        tail->next_outputsec = inp;
        out->isection_tail = inp;
        inp->out = out;
        return 0;
}

static
int should_ignore_section(struct input_section *inp)
{
        /* Ignore strtab, symtab - those should be synthesized by the linker */
        switch(inp->sh_type) {
                case SHT_STRTAB:
                case SHT_SYMTAB:
                        return 1;
                case SHT_REL:
                case SHT_RELA:
                        /* TODO: -r support */
                        return 1;
                default:
                        return 0;
        }
}

struct output_section *elf_merge_sections(struct input_file **files, u32 nfiles,
                                          u32 *p_noutput)
{
        struct output_section *out = NULL;
        struct input_section *inp = NULL;
        u32 nr_output = 0;
        u32 capacity = 0;
        u32 i, j;

        for (i = 0; i < nfiles; i++) {
                struct input_file *file = files[i];
                for (j = 0; j < file->nsections; j++) {
                        inp = &file->sections[j];

                        if (should_ignore_section(inp))
                                continue;

                        if (try_merge(out, nr_output, inp) < 0) {
                                goto create_out;
                        }
                        /* XXX yikes. */
                loop:;
                }
        }

        /* TODO: Sorting <within> certain output sections by alignment is
         * desired, in order to save space. This will require an array instead
         * of a linked list (exception: .init, .fini, .ctor, .dtor, .init_array,
         * .fini_array).
         */

        *p_noutput = nr_output;

        return out;
create_out:
        if (nr_output + 1 > capacity) {
                capacity = capacity == 0 ? 8 : capacity << 1;
                out = reallocarray(out, capacity, sizeof(struct output_section));
                if (!out) {
                        warn("elf_merge_sections: reallocarray");
                        return NULL;
                }
        }

        struct output_section *sec = &out[nr_output++];
        memset(sec, 0, sizeof(*sec));
        sec->name = strdup(inp->name);
        if (!sec->name) {
                warn("strdup");
                return NULL;
        }

        verbose("Creating output section %s with input section %s(%s)\n", sec->name, inp->name, inp->file->name);

        /* Replace the 1-as-0 encoding here, to avoid further pain */
        sec->max_alignment = inp->sh_addralign ?: 1;
        sec->size = inp->sh_size;
        sec->isection_head = sec->isection_tail = inp;
        inp->out = sec;
        goto loop;
}
