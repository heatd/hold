/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <stdbool.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <hold.h>

#include <stdio.h>

int elf_do_link(struct hold_options *opts);

static
int is_not_elfish(const char *filename)
{
        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
                warn("%s", filename);
                return 2;
        }

        char magic[8];
        if (read(fd, magic, sizeof(magic)) < sizeof(magic)) {
                warn("%s: Failed to read magic", filename);
                close(fd);
                return 3;
        }

        close(fd);

        return !!memcmp(magic, "\x7f""ELF", 4) && !!memcmp(magic, "!<arch>\n", 8);
}

int hold_do_link(struct hold_options *opts)
{
        if (is_not_elfish(opts->input_files[0])) {
                warnx("%s: unsupported backend", opts->input_files[0]);
                return 1;
        }

        return elf_do_link(opts);
}
