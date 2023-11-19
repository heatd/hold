==============================
HOLD - heat's Onyx link editor
==============================

hold is a simple ELF linker. It only works for POSIX-like platforms.

Building
================

Use meson to build hold, as such::

  meson build/
  ninja -C build/

The executable will then be at ``build/src/ld.hold``.


Disclaimer
================

This was a fun weekend project and is very incomplete, don't expect it to work properly :)
