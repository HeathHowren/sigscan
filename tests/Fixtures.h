#pragma once

#include "FakeMemory.h"

#include "sigscan/sigscan.hpp"

namespace sigscan::test {

// A 64-bit module shaped like the code Signature Lab signs: a function that
// reads a global through a RIP-relative mov, a lea that takes the global's
// address, and a call to the function. The byte encodings are the same the MSVC
// compiler emits and match Signature Lab's own X64Fixture, so a signature made
// by Signature Lab and resolved here lands on the same address.
struct X64Fixture {
    static constexpr std::uint64_t kBase = 0x140000000;
    static constexpr std::uint64_t kFunc = 0x140001000; // mov rax, [rip+global]; test; je
    static constexpr std::uint64_t kLea = 0x140001020;  // lea rcx, [rip+global]; ret
    static constexpr std::uint64_t kCall = 0x140001030; // call func; ret
    static constexpr std::uint64_t kGlobal = 0x140003000;

    FakeMemory memory{kBase, 0x4000};

    X64Fixture() {
        // 48 8B 05 <disp32>            mov rax, [rip+global]
        memory.write(kFunc, {0x48, 0x8B, 0x05});
        memory.write32(kFunc + 3, rel32(kFunc, 7, kGlobal));
        // 48 85 C0 74 05               test rax, rax; je +5
        memory.write(kFunc + 7, {0x48, 0x85, 0xC0, 0x74, 0x05});
        // 48 8D 0D <disp32> C3         lea rcx, [rip+global]; ret
        memory.write(kLea, {0x48, 0x8D, 0x0D});
        memory.write32(kLea + 3, rel32(kLea, 7, kGlobal));
        memory.write(kLea + 7, {0xC3});
        // E8 <rel32> C3                call func; ret
        memory.write(kCall, {0xE8});
        memory.write32(kCall + 1, rel32(kCall, 5, kFunc));
        memory.write(kCall + 5, {0xC3});
        // A pointer-sized value at the global, so a [rip+disp] read has a target.
        memory.write64(kGlobal, 0xCAFEF00DDEADBEEFull);
    }
};

// Applies sigscan's resolve rule to the bytes at a match, the way a reader's
// scanner would. Kept identical in spirit to Signature Lab's test resolve.
inline std::uint64_t resolveAt(const FakeMemory& memory, ReferenceKind kind, std::uint64_t matchVa, std::size_t fieldOffset,
                               std::uint8_t instrLen) {
    const std::uint8_t* at = memory.bytes().data() + (matchVa - memory.base());
    return resolve(kind, at, fieldOffset, matchVa, instrLen);
}

} // namespace sigscan::test
