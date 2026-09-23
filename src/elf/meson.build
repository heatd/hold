sources += files(
  'archive.c',
  'link.c',
  'output_sections.c',
  'relocs.c',
  'writer.c',
  'x86_64.c',
)

cc = meson.get_compiler('c')
cc.has_header('elf.h', required: true)
