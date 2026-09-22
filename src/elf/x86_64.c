/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <elf.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <hold.h>

#include <elf/elf.h>
#include <elf/output_section.h>

#define REL64(val) *p = (val)
#define REL32(val) *p32 = (val)

static
int relax_gotpcrelx(u8 *p, muptr S, muptr P)
{
	u32 *p32 = (u32 *) p;
	u8 op = p[-2];
	u8 modrm = p[-1];

	if (op == 0x8b) {
		/* mov sym@GOTPCREL(%rip), %reg -> lea sym(%rip), %reg */
		p[-2] = 0x8d;
		REL32(S - P);
		return 0;
	}

	return -1;
}

static
int do_reloc(struct relocation *reloc, struct input_section *inp, u8 *mapping)
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

	if (!maybe_resolve(reloc->sym, inp, reloc))
		return -1;

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
		case R_X86_64_REX_GOTPCRELX:
			if (A == -4) {
				if (relax_gotpcrelx(p8, S, P) == 0)
					break;
			}
			/* fallthrough */
		default:
			warnx("%s:(%s+0x%lx): Unhandled relocation type %x",
					inp->file->name, inp->name, reloc->offset,
					reloc->rel_type);
			return -1;
	}

	return 0;
}

void elf_do_relocs(struct input_file *file, struct relocation *relocs, u32 nrelocs, u8 *mapping)
{
	u32 i, errors = 0;

	for (i = 0; i < nrelocs; i++) {
		struct input_section *section = &file->sections[relocs[i].section];
		/* HACK: Let's only handle sections that have been mapped in the binary.
		 * At the moment, SHF_ALLOC.
		 */
		if (section->out && section->out->offset)
		{
			if (do_reloc(&relocs[i], section, mapping) < 0) {
				if (errors++ >= 100)
					exit(1);
			}
		}
	}

	if (errors)
		exit(1);
}
