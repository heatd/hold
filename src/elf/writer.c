/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#include <elf/output_section.h>
#include <elf.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include <hold.h>
#include <elf/elf.h>

struct program_header {
        struct output_section **sections;
        muptr address;
        muptr memsize;
        muptr filesz;
        muptr alignment;
        u32 nr_sections;
        u32 type;
        u64 offset;
        u32 flags;
};

static
int write_elf_header(struct elf_writer *writer, int fd, uptr entry_point)
{
        elf_ehdr ehdr;
        /* TODO: ET_DYN */
        ehdr.e_type = ET_EXEC;
        ehdr.e_entry = 0;
        ehdr.e_version = EV_CURRENT;
        memcpy(&ehdr.e_ident, "\x7f""ELF", 4);
        ehdr.e_ident[EI_CLASS] = ELFCLASS64;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ehdr.e_ident[EI_ABIVERSION] = 1;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        memset(&ehdr.e_ident[EI_PAD], 0, 5);
        ehdr.e_entry = entry_point;
        ehdr.e_machine = EM_X86_64;
        ehdr.e_ehsize = sizeof(ehdr);
        ehdr.e_phoff = sizeof(ehdr);
        ehdr.e_phentsize = sizeof(elf_phdr);
        ehdr.e_phnum = writer->nr_phdrs;

        return write(fd, &ehdr, sizeof(ehdr));
}

static
int cmp_output_secs(const void *a, const void *b)
{
        struct output_section *s1 = *(void **) a;
        struct output_section *s2 = *(void **) b;

        struct input_section *inp1 = s1->isection_head;
        struct input_section *inp2 = s2->isection_head;

        if ((inp1->sh_type & SHT_NOBITS) != (inp2->sh_type & SHT_NOBITS)) {
                /* Take care of moving BSS down the program header */
                return inp1->sh_type & SHT_NOBITS ? 1 : -1;
        }

        /* sh_addralign can encode 1 as 0 - replace it with 1 */
        muptr align0 = s1->max_alignment ?: 1;
        muptr align1 = s2->max_alignment ?: 1;

        if (align0 > align1)
                return -1;
        else if (align0 < align1)
                return 1;
        return 0;
}

static
const char *text_perms(u32 flags)
{
        switch (flags)
        {
                case PF_R | PF_X:
                        return "PF_R|PF_X";
                case PF_R | PF_W:
                        return "PF_R|PF_W";
                case PF_R:
                        return "PF_R";
                default:
                        abort();
        }
}

static
int gather_sections_for_phdr(struct program_header *phdr, int seen, struct elf_writer *writer)
{
        struct output_section **secs;
        u32 i, cursec = 0;

        /* The minimum alignment for a program header is usually PAGE_SIZE.
         * Note that ARM64 linux deviates from 4KiB by asking for 64KiB.
         */
        int align = 0x1000;

        secs = calloc(seen, sizeof(struct output_section*));
        if (!secs)
                return -1;

        for (i = 0; i < writer->nr_output_secs; i++) {
                struct output_section *sec = &writer->out_section[i];
                /* Infer flags and permissions from the first input section
                 * associated with this output section.
                 */
                struct input_section *inp = sec->isection_head;

                if (!(inp->sh_flags & SHF_ALLOC))
                        continue;
                /* This logic is simplified by knowing that the caller can only
                 * create PF_R, PF_R | PF_X, and PF_R | PF_W.
                 */
                if ((inp->sh_flags & SHF_WRITE && phdr->flags & PF_W) ||
                    (inp->sh_flags & SHF_EXECINSTR && phdr->flags & PF_X) ||
                    (!(inp->sh_flags & (SHF_WRITE | SHF_EXECINSTR)) && (phdr->flags & (PF_R|PF_W|PF_X)) == PF_R)) {
                        verbose("Output section %s assigned to phdr %s\n", sec->name, text_perms(phdr->flags));
                        secs[cursec++] = sec;
                        if (sec->max_alignment > align)
                                align = sec->max_alignment;
                }
        }

        /* Sort sections between a phdr on alignment and if bss; this should
         * not have any behavioral impact.
         */
        qsort(secs, cursec, sizeof(struct output_section *), cmp_output_secs);

        if (option_verbose) {
                verbose("reordered output sections:\n");
                for (i = 0; i < cursec; i++) {
                        struct output_section *sec = secs[i];
                        verbose("output section[%u]: %s (align %lu)\n", i, sec->name, sec->max_alignment);
                }
        }

        phdr->alignment = align;

        for (i = 0; i < cursec; i++) {
                struct output_section *section = secs[i];
                struct output_section *next = i + 1 < cursec ? secs[i + 1] : NULL;

                if (next) {
                        /* Align the size of this output section with the next's align */
                        section->size = (section->size + next->max_alignment - 1) & -next->max_alignment;
                }

                phdr->memsize += section->size;
                if (!(section->isection_head->sh_type & SHT_NOBITS)) {
                        /* Add this to filesz if !BSS */
                        phdr->filesz += section->size;
                }
        }

        phdr->type = PT_LOAD;
        phdr->sections = secs;
        phdr->nr_sections = cursec;

        return 0;
}

#define DEFAULT_BASE_ADDRESS 0x400000

static void pretty_print_phdr(struct program_header *header);

static
void assign_input_sections_off(struct output_section *out)
{
        struct input_section *inp;
        muptr off = 0;
        muptr size = out->size;

        for (inp = out->isection_head; inp != NULL; inp = inp->next_outputsec) {
                u32 misalign;
                muptr total;

                inp->output_off = alignToPowerOf2(off, inp->sh_addralign ?: 1);
                misalign = inp->output_off - off;

                total = misalign + inp->sh_size;
                assert(size >= total);
                size -= total;
                off += total;
                verbose("Input section %s(%s) at output %s + %lx\n", inp->name,
                        inp->file->name, out->name, inp->output_off);
        }
}

static
void assign_output_section_addr_off(struct program_header *phdr, u32 to_skip)
{
        muptr addr = phdr->address + to_skip;
        muptr base_offset = phdr->offset + to_skip;
        muptr size = phdr->memsize;
        u32 i;

        for (i = 0; i < phdr->nr_sections; i++) {
                u32 misalign = 0;
                muptr total = 0;
                struct output_section *os = phdr->sections[i];
                assert(os->size <= size);

                os->address = alignToPowerOf2(addr, os->max_alignment);
                misalign = os->address - addr;
                os->offset = base_offset + misalign;

                total = misalign + os->size;
                assert(size >= total);
                size -= total;
                addr += total;

                assign_input_sections_off(os);

                verbose("Section %s assigned address %lx, file offset %lx\n", os->name, os->address, os->offset);
        }

        /* TODO: Assert on this? The first LOAD seems to be having issues here... */
        verbose("Leftover: %lx\n", size);
}

static
int create_program_headers(struct elf_writer *writer)
{
        /* Some comments on the general strategy for laying out phdrs.
         * General PHDR layout:
         *     1) R-- segment (for .rodata, .eh_table, etc).
         *     2) R-X segment (.text, .init, .ctors, etc).
         *     3) RW- segment (.data, .bss, etc.)
         *        Note that .bss is always the tail of this section, and the
         *        executable in general.
         * We lay out the read-only segment in first place, because then we can
         * use a single segment/mapping for EHDR + PHDR + rodata. Then the text
         * segment, because the data segment must be last, because of bss. The bss
         * needs to be last, for traditional reasons: UNIX systems start their brk
         * from ebss onwards.
         *
         * It's also worth noting here that all sorts of auxiliary information
         * that will never be mapped (lets say, section headers, symbols, ELF
         * strings) will go after all mapped data (so after .data in the file).
         * This is to avoid having more crap mapped than we need.
         *
         * So in general the layout is:
         *    [EHDR]
         *    [PHDRS]  # Needed for dynamic linking/PIE
         *    [SEGMENT 0...N]  # Layout described above
         *    [Extra data ]  # Section headers, ELF strings, symbols
         */

        /* The logic here is not horrendous, since we don't support more than the 3 standard segments.
         * Let's go through output sections and check what permissions we do see (RO, RX, RW). Then infer
         * the number of program headers from that.
         */
        int seen[3] = {};
        int nr_program_headers = 1; /* 1 for PT_PHDRS */
        u32 i, next_phdr;
        u64 fileoff;
        muptr base_address = DEFAULT_BASE_ADDRESS;

        for (i = 0; i < writer->nr_output_secs; i++) {
                struct output_section *sec = &writer->out_section[i];
                /* Infer flags and permissions from the first input section
                 * associated with this output section.
                 */
                struct input_section *inp = sec->isection_head;

                if (!(inp->sh_flags & SHF_ALLOC))
                        continue;
                if (inp->sh_flags & SHF_WRITE)
                        seen[2]++;
                else if (inp->sh_flags & SHF_EXECINSTR)
                        seen[1]++;
                else
                        seen[0]++;
        }

        /* Thought: LLD always maps the EHDR/PHDR read-only, even when there's
         * no read-only segment. This makes sense from a security PoV, but is
         * it meaningful? For now, let's map the phdrs RX or even RW.
         */
        for (i = 0; i < 3; i++)
                seen[i] ? nr_program_headers++ : 0;

        verbose("nrprog %u\n", nr_program_headers);

        writer->phdr = calloc(nr_program_headers, sizeof(struct program_header));
        if (!writer->phdr) {
                warn("create_program_headers");
                return -1;
        }

        writer->nr_phdrs = nr_program_headers;

        /* PT_PHDR: To be patched up later, but make the offset point to the
         * future program headers. We can hardcode this as sizeof(ehdr).
         */
        writer->phdr[0].type = PT_PHDR;
        writer->phdr[0].offset = writer->phdr[0].address = sizeof(elf_ehdr);
        writer->phdr[0].address += base_address;
        writer->phdr[0].alignment = 8;
        writer->phdr[0].filesz = writer->phdr[0].memsize = sizeof(elf_phdr) * nr_program_headers;
        writer->phdr[0].flags = PF_R;

        /* We can start at 0, as long as we keep in mind that
         * up until phdr[0].filesz we're not allowed to put any sections.
         */
        fileoff = 0;

        if (option_verbose)
                pretty_print_phdr(&writer->phdr[0]);

        next_phdr = 1;

        for (i = 0; i < 3; i++) {
                struct program_header *phdr;
                if (!seen[i])
                        continue;

                phdr = &writer->phdr[next_phdr++];

                switch(i)
                {
                        case 0:
                                phdr->flags = PF_R;
                                break;
                        case 1:
                                phdr->flags = PF_R | PF_X;
                                break;
                        case 2:
                                phdr->flags = PF_R | PF_W;
                                break;
                }

                if (gather_sections_for_phdr(phdr, seen[i], writer) < 0)
                        return -1;
                /* Note on alignment: p_align specifies the alignment of a segment.
                 * This is specified by the spec to mean that p_vaddr and p_offset
                 * (both modulo p_align) must be congruent.
                 * This means that address % p_align == offset % p_align.
                 * Or in pow2 terms, address & (p_align - 1) == offset & (p_align - 1).
                 */
                /* XXX: We're not being able to lay this out optimally.*/
                base_address = alignToPowerOf2(base_address, phdr->alignment);
                phdr->address = base_address;
                fileoff = align_to(fileoff, phdr->alignment, phdr->address);
                phdr->offset = fileoff;

                if (i == 0) {
                        u64 phdr_end = phdr[-1].filesz + phdr[-1].offset;
                        /* First section, take the headers into account for the size */
                        phdr->memsize += phdr_end;
                        phdr->filesz += phdr_end;
                }

                assign_output_section_addr_off(phdr, i == 0 ? phdr[-1].offset + phdr[-1].filesz : 0);

                fileoff += phdr->filesz;
                base_address += phdr->memsize;
                if (option_verbose)
                        pretty_print_phdr(phdr);
        }

        return 0;
}

static
void write_phdrs(struct elf_writer *writer, u8 *mapping)
{
        elf_phdr *p = (elf_phdr *) (mapping + sizeof(elf_ehdr));
        u32 i;

        for (i = 0; i < writer->nr_phdrs; i++, p++) {
                struct program_header *phdr = &writer->phdr[i];
                p->p_type = phdr->type;
                p->p_align = phdr->alignment;
                p->p_flags = phdr->flags;
                p->p_memsz = phdr->memsize;
                p->p_filesz = phdr->filesz;
                p->p_offset = phdr->offset;
                p->p_vaddr = p->p_paddr = phdr->address;
        }
}

static
void write_section(int fd, struct input_section *inp, u8 *mapping)
{
        if (inp->sh_type == SHT_NOBITS)
                return;
        struct output_section *out = inp->out;
        verbose("Copying [%lu, %lu] to %lu\n", inp->sh_offset, inp->sh_offset + inp->sh_size - 1, out->offset + inp->output_off);
        if (pread(fd, mapping + out->offset + inp->output_off, inp->sh_size, inp->sh_offset) < 0) {
                err(1, "write_section: pread");
        }
}

static
void input_write_segs(struct input_file *file, u8 *mapping)
{
        int fd;
        u32 i;

        fd = open(file->name, O_RDONLY);
        if (fd < 0)
                err(1, "%s", file->name);

        for (i = 0; i < file->nsections; i++) {
                struct input_section *inp = &file->sections[i];

                /* TODO: This is kind of random */
                if (inp->out && inp->out->offset)
                        write_section(fd, inp, mapping);
        }

        close(fd);
}

static
void write_segments(struct elf_writer *writer, u8 *mapping)
{
        u32 i;

        for (i = 0; i < writer->nfiles; i++) {
                struct input_file *inp = writer->files[i];
                input_write_segs(inp, mapping);
        }
}

static
void relocate(struct elf_writer *writer, u8 *mapping)
{
        u32 i;

        for (i = 0; i < writer->nfiles; i++) {
                struct input_file *inp = writer->files[i];
                elf_do_relocs(inp, inp->relocs, inp->nrelocs, mapping);
        }
}

/* Taking an elf writer, write an output, linked and relocated ELF file */
int elf_do_write(struct elf_writer *writer)
{
        unsigned long file_size;
        u8 *mapping;
        struct symbol *entry;
        int st;
        int fd = open(writer->options->output_name, O_RDWR | O_CREAT | O_TRUNC, 0755);
        if (fd < 0) {
                warn("Failed to open %s", writer->options->output_name);
                return -1;
        }

        if (create_program_headers(writer) < 0)
                return -1;

        relocate_symbols();

        file_size = writer->phdr[writer->nr_phdrs - 1].offset +
                writer->phdr[writer->nr_phdrs - 1].filesz;

        if (ftruncate(fd, file_size) < 0) {
                warn("ftruncate");
                return -1;
        }

        mapping = mmap(NULL, file_size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED) {
                warn("mmap");
                return -1;
        }

        entry = lookup_symtable("_start");
        if (!entry) {
                warnx("_start not found");
                return -1;
        }

        st = write_elf_header(writer, fd, entry->value);
        if (st < 0)
                return -1;

        write_phdrs(writer, mapping);
        write_segments(writer, mapping);
        relocate(writer, mapping);

        munmap(mapping, file_size);
        return 0;
}

void elf_writer_destroy(struct elf_writer *writer)
{
        u32 i;

        for (i = 0; i < writer->nr_output_secs; i++) {
                struct output_section *sec = &writer->out_section[i];
                free((void *) sec->name);
        }

        free(writer->out_section);

        for (i = 0; i < writer->nr_phdrs; i++) {
                struct program_header *phdr = &writer->phdr[i];
                free(phdr->sections);
        }

        free(writer->phdr);
}

static
void pretty_print_phdr(struct program_header *phdr)
{
        printf("  Type           Offset             VirtAddr           PhysAddr\n"
               "                 FileSiz            MemSiz              Flags  Align\n");
        const char *type_text = "LOAD";
        if (phdr->type == PT_PHDR)
                type_text = "PHDR";
        char flags[4];
        sprintf(flags, "%c%c%c", phdr->flags & PF_R ? 'R' : ' ',
                phdr->flags & PF_W ? 'W' : ' ', phdr->flags & PF_X ? 'E' : ' ');
#define ADDR_SPEC "%#018lx"
        printf("  %-14s " ADDR_SPEC " " ADDR_SPEC " " ADDR_SPEC"\n", type_text, phdr->offset, phdr->address, phdr->address);
        printf("                 " ADDR_SPEC " " ADDR_SPEC " %-6s %#lx\n", phdr->filesz, phdr->memsize, flags, phdr->alignment);

}
