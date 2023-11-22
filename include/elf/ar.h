/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#ifndef ELF_AR_H
#define ELF_AR_H

#include <string.h>

#define AR_MAGIC "!<arch>\n"
#define	ARFMAG	"`\n"

struct ar_hdr {
        char ar_name[16];
        char ar_date[12];
        char ar_uid[6];
        char ar_gid[6];
        char ar_mode[8];
        char ar_size[10];
        char ar_fmag[2];
};

static inline int is_ar_archive(const void *buf)
{
        return !memcmp(buf, AR_MAGIC, strlen(AR_MAGIC));
}

struct input_file;
struct symbol;

int parse_ar(struct input_file *file, const void *mapping, unsigned long filesz);
int resolve_lazy(struct symbol *sym);

#endif
