/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include "hold.h"
#include <getopt.h>

#include <stdio.h>

static
void usage(void)
{
        printf("hold: usage: ld.hold [OBJECT FILES] -o output_name\n");
}

int option_verbose;

const struct option options[] = {
        {"output", required_argument, NULL, 'o'},
        {"verbose", no_argument, &option_verbose, 1},
        {}
};

int main(int argc, char **argv)
{
        struct hold_options opts;
        opts.output_name = "a.out";
        opts.entry_point = "_start";

        if (argc == 1) {
                usage();
                return 1;
        }

        int optindex = 0;
        int opt;
        while ((opt = getopt_long(argc, argv, "o:v", options, &optindex)) != -1)
        {
                switch (opt)
                {
                        case 'o':
                                opts.output_name = optarg;
                                break;
                        case 'v':
                                option_verbose = 1;
                                break;
                }
        }

        if (optind == argc) {
                usage();
                return 1;
        }

        if (option_verbose) {
                int i;
                printf("ld.hold: linking");
                for (i = optind; i < argc; i++) {
                        printf(" %s", argv[i]);
                }
                printf("\n");
        }

        opts.input_files = (const char **) &argv[optind];
        opts.ninput_files = argc - optind;

        return hold_do_link(&opts);
}
