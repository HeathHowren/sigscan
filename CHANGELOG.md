# Changelog

All notable changes to sigscan are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-25

The first release.

### Added

- **A parser for every common signature form.** x64dbg (`48 8B ?? ??`, with
  `4?` nibble wildcards and no-separator text), IDA (`48 8B ? ?`), code-style
  bytes with an `x`/`?` or `0b` mask, a C++ array with mask, and a Cheat Engine
  or Pointer Lab `aobscanmodule(...)` line. These are the forms Signature Lab
  writes, so a signature made there parses here unchanged.
- **A parser that reports what is wrong.** A mask whose length does not match
  its bytes, a lone hex digit, a three-digit array value, or a stray character
  is refused with a reason, not silently treated as "no match".
- **An SSE2 scanner with an AVX2 path and a scalar fallback.** The backend is
  chosen at run time from the CPU. `find` returns the first match, `findAll`
  returns them all. A pattern with no fixed byte falls back to scalar.
- **A page-aware region scanner.** `scanReader` reads a region page by page
  through a `MemoryReader` and carries a tail between windows, so a match that
  straddles a page or window boundary is found once. An unreadable page ends
  the run; no match spans a gap that cannot be read.
- **On-disk PE scanning.** `scanPeFile` scans a PE's raw bytes and reports each
  match by file offset and, where the offset is backed by a section or the
  headers, its RVA.
- **Live process module scanning on Windows.** `scanProcessModule` attaches
  read-only, finds a module by name, and scans it with the same region scanner.
- **Resolve helpers that mirror Signature Lab's resolve line.** RIP-relative
  displacement, near call or jump target, an absolute 32- or 64-bit field, and
  a `[rip+disp]` read that follows the operand and reads the pointer there.
- **A command-line tool, `sigscan.exe`.** `--file` for an on-disk PE with RVA
  and file offset, `--pid` with `--module` for a live process, `--first` and
  `--limit`. The pattern may be in any of the parsed forms.
- The library is one header, `include/sigscan/sigscan.hpp`, C++20, with no
  third-party dependencies. The C runtime is linked statically into the CLI.
