/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#ifndef ELF_OUTPUT_SECTION_H_INCLUDED
#define ELF_OUTPUT_SECTION_H_INCLUDED

#include <elf/elf.h>

struct output_section {
	const char *name;
	struct input_section *isection_head, *isection_tail;
	u32 sh_flags;
	u32 sh_type;
	u32 sh_link;
	u32 sh_entsize;
	u32 sh_info;
	u32 index;
	muptr max_alignment;
	muptr address;
	muptr offset;
	muptr size;
};

#endif

