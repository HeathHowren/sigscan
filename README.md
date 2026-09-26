<p align="center">
  <img src="docs/logo.svg" width="96" alt="sigscan logo">
</p>

# sigscan

Parse a byte signature in any common form and find it.

[![CI](https://github.com/HeathHowren/sigscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/sigscan/actions/workflows/ci.yml)

sigscan is a single-header C++20 library and a small command-line tool. It reads
a signature written in x64dbg, IDA, code-and-mask, C++ array or Cheat Engine and
Pointer Lab `aobscanmodule(...)` form, then finds it in a byte span, an on-disk
PE, or a live process module on Windows. It is the read side of
[Signature Lab](https://github.com/HeathHowren/Signature-Lab): the forms
Signature Lab writes are the forms sigscan parses, and its resolve helpers
mirror the resolve line Signature Lab prints.

sigscan is written by Heath Howren
([Cyborg Elf](https://www.youtube.com/c/cyborgelf)) of
[Game Reversal Club](https://gamereversal.club). It is the consumer side of
[Signature Lab](https://github.com/HeathHowren/Signature-Lab), and the pattern
scanner behind the signature-scanning chapter of
[*The Game Hacker's Handbook*](https://gamereversal.club/books/game-hackers-handbook/).

```
pattern 48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B D9  (20 bytes, 4 wildcards)
file    PointerLabTutorial.exe (PE32+, 7 sections)
backend AVX2
match   RVA 0x00001670  file offset 0x00000A70  .text
1 match
```

*Real output. The signature is the worked example from Signature Lab's own
README; sigscan finds the same function, at the same RVA, in a local build of
the Pointer Lab tutorial (`PointerLabTutorial.exe`).*

## What it does

- **Reads every common form.** x64dbg (`48 8B ?? ??`, with `4?` nibble
  wildcards and text with no separators), IDA (`48 8B ? ?`), code-style bytes
  with an `x`/`?` or `0b` mask, a C++ array with mask, and a Cheat Engine or
  Pointer Lab `aobscanmodule(...)` line. Every form round-trips against the
  bytes Signature Lab emits.
- **Reports a malformed pattern instead of ignoring it.** A mask whose length
  does not match its bytes, a lone hex digit or a stray character is refused
  with a reason. A mask mismatch that was silently ignored would make the
  scanner report "not found" and leave you to guess why.
- **Scans with SSE2, AVX2 or a scalar fallback.** The backend is chosen at run
  time from the CPU. It returns the first match or all matches.
- **Handles page boundaries and partial reads.** The region scanner reads a
  process or image page by page and carries a tail between windows, so a match
  that straddles a boundary is found once. An unreadable page ends the run; a
  match is never reported across a gap that could not be read.
- **Scans an on-disk PE.** It reports each match by file offset and by RVA, so
  a signature can be checked against a file before the program is running.
- **Scans a live process module on Windows.** It attaches read-only, finds the
  module by name, and reports each match by virtual address and RVA.
- **Resolves a reference back to its target.** RIP-relative displacement, a
  near call or jump target, an absolute 32- or 64-bit field, and a `[rip+disp]`
  read, using the same arithmetic as Signature Lab's resolve line.
- **One header, no dependencies.** `include/sigscan/sigscan.hpp` includes only
  the standard library, and `windows.h` for the live-process code.

## Performance

On one machine (AVX2, a 256 MiB pseudo-random buffer scanned for a 12-byte
pattern with wildcards, best of five passes):

```
backend    AVX2
buffer     256 MiB
best pass  22.935 ms
throughput 10.90 GB/s
```

The scalar and SSE2 paths are slower; the point of the number is that the whole
buffer is scanned, not a shortcut. Run `sigscan-bench` to measure your own.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/sigscan/releases). It contains:

```
sigscan.exe             the command-line tool
include/sigscan/sigscan.hpp   the library, if you want to drop it into a project
LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES.md
```

Both an x64 and an x86 zip are built. The library is header-only, so to use it
in your own project you only need the header; the exe is a convenience.

The binary is unsigned. Antivirus software may flag a tool that reads another
process's memory. Build from source if you would rather not take a binary on
trust.

## Quick start

Use the library from your own code:

```cpp
#include "sigscan/sigscan.hpp"
#include <span>

auto sig = sigscan::parse("48 8B 05 ?? ?? ?? ??");
if (!sig) {
    // sig.error says what was wrong with the text
}
std::span<const std::uint8_t> haystack = /* your bytes */;
if (auto at = sigscan::find(haystack, sig.pattern)) {
    // *at is the offset of the first match
}
for (std::size_t at : sigscan::findAll(haystack, sig.pattern)) {
    // every match
}
```

Or use the tool. The pattern is every argument that is not an option, so it can
be quoted or left bare:

```
sigscan --file game.exe 48 8B 05 ?? ?? ?? ??
sigscan --file game.exe "48 8B 05 ? ? ? ?"
sigscan --pid 1234 --module game.exe --first "\x48\x8B\x05" "xxx"
```

To scan a live process, run as the same user as the target, and match its
bitness: the 32-bit `sigscan.exe` reads 32-bit processes, the 64-bit one reads
64-bit processes. Reading a process owned by another user or an elevated one
needs the matching privileges.

## Library reference

Everything is in namespace `sigscan`, in `include/sigscan/sigscan.hpp`.

| Function | What it does |
|---|---|
| `parse(text)` | Parse any form into a `ParseResult` (a `Pattern`, or an error string). |
| `format(pattern, form, ...)` | Render a pattern in one of the `Format` forms. |
| `find(span, pattern)` | The first match offset, or nothing. |
| `findAll(span, pattern, limit)` | Every match offset, in order. |
| `scanReader(reader, base, size, pattern, ...)` | Match a page-readable region through a `MemoryReader`. |
| `scanPeFile(path, pattern, ...)` | Match an on-disk PE; each hit has a file offset and, where mapped, an RVA. |
| `scanProcessModule(pid, module, pattern, ...)` | Match a live module on Windows; each hit has a VA and RVA. |
| `resolve(kind, at, fieldOffset, matchVa, instrLen)` | A match back to the address it refers to. |
| `readRipRelative(reader, ...)` | Follow a `[rip+disp]` operand and read the pointer there. |
| `activeBackend()` | Which scan backend the CPU selected (`Scalar`, `Sse2`, `Avx2`). |

The `MemoryReader` interface has one method to implement, `read`, so the same
scanner can run over a live process, a mapped file, or a test buffer.

`scanProcessModule` and `findModule` are declared for every build but defined
only in the translation unit that defines `SIGSCAN_IMPLEMENTATION` before
including the header, so `windows.h` is pulled in exactly once. `sigscan.exe`
does this; if you call these functions yourself, define it in one `.cpp`.

## Build

Requirements: Visual Studio 2022 with the C++ workload and CMake 3.28 or newer.
The CMake that ships with Visual Studio is recent enough. The header itself is
portable C++20; this build is set up for MSVC.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For the 32-bit build, configure a second tree with `-A Win32`. The tests fetch
Catch2, pinned by tag, on the first configure; nothing else is downloaded. To
produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

## Intended use

sigscan is for studying software **you own or are authorized to analyze**: your
own programs, single-player games, CTF binaries, and the Handbook's lab targets.
Reading the memory of online or competitive games will very likely trip
anti-cheat software and get the account banned. That decision is yours; this
tool does not make it for you.

## License

MIT; see [LICENSE](LICENSE). The library has no third-party dependencies. The
tests use Catch2 (Boost Software License 1.0), which is not part of the library
or the tool. Details are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
