/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Pedro Falcato */
#ifndef HOLD_H_INCLUDED
#define HOLD_H_INCLUDED

#include <assert.h>
#include <elf.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uptr;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef intptr_t sptr;

struct hold_options {
        /* First set of options: frontend options */
        /* Output name. Defaults to a.out */
        const char *output_name;

        /* Array of input files */
        const char **input_files;
        int ninput_files;

        /* Entry point symbol name: defaults to _start */
        const char *entry_point;

        /* Second set of options: middle-end options, from link.c to the respective backend */
        uptr base_address;
};

extern int option_verbose;

#define verbose(...)                 \
do {                                 \
        if (option_verbose)          \
                printf(__VA_ARGS__); \
} while (0)

int hold_do_link(struct hold_options *options);

#ifndef __has_feature
#define __has_feature(a) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define HOLD_ASAN_ENABLED 1
#endif

/* __alignTo, alignToPowerOf2, alignTo were taken from LLVM LLD, Apache 2.0 licensed */

static inline u64 __alignTo(u64 Value, u64 Align) {
  assert(Align != 0u && "Align can't be 0.");
  return (Value + Align - 1) / Align * Align;
}

static inline u64 alignToPowerOf2(u64 Value, u64 Align) {
  assert(Align != 0 && (Align & (Align - 1)) == 0 &&
         "Align must be a power of 2");
  return (Value + Align - 1) & -Align;
}

/// If non-zero \p Skew is specified, the return value will be a minimal integer
/// that is greater than or equal to \p Size and equal to \p A * N + \p Skew for
/// some integer N. If \p Skew is larger than \p A, its value is adjusted to '\p
/// Skew mod \p A'. \p Align must be non-zero.
///
/// Examples:
/// \code
///   alignTo(5, 8, 7) = 7
///   alignTo(17, 8, 1) = 17
///   alignTo(~0LL, 8, 3) = 3
///   alignTo(321, 255, 42) = 552
/// \endcode
static inline u64 align_to(u64 Value, u64 Align, u64 Skew) {
  assert(Align != 0u && "Align can't be 0.");
  Skew %= Align;
  return __alignTo(Value - Skew, Align) + Skew;
}

#endif
