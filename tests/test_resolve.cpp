#include "Fixtures.h"

#include "sigscan/sigscan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <span>

using namespace sigscan;
using test::X64Fixture;

TEST_CASE("a RIP-relative mov resolves to the global it reads", "[resolve]") {
    X64Fixture f;
    const std::uint8_t* at = f.memory.bytes().data() + (X64Fixture::kFunc - X64Fixture::kBase);
    // 48 8B 05 <disp32>: the disp32 field starts at offset 3, instruction is 7 bytes.
    const std::uint64_t target = resolveRipRelative(at, 3, X64Fixture::kFunc, 7);
    CHECK(target == X64Fixture::kGlobal);
    CHECK(resolve(ReferenceKind::RipRelative, at, 3, X64Fixture::kFunc, 7) == X64Fixture::kGlobal);
}

TEST_CASE("a lea resolves to the global whose address it takes", "[resolve]") {
    X64Fixture f;
    const std::uint8_t* at = f.memory.bytes().data() + (X64Fixture::kLea - X64Fixture::kBase);
    // 48 8D 0D <disp32>: field at 3, instruction 7 bytes.
    CHECK(resolveRipRelative(at, 3, X64Fixture::kLea, 7) == X64Fixture::kGlobal);
}

TEST_CASE("a near call resolves to the function it calls", "[resolve]") {
    X64Fixture f;
    const std::uint8_t* at = f.memory.bytes().data() + (X64Fixture::kCall - X64Fixture::kBase);
    // E8 <rel32>: field at 1, instruction 5 bytes. Same arithmetic as RIP-relative.
    CHECK(resolveCallTarget(at, 1, X64Fixture::kCall, 5) == X64Fixture::kFunc);
    CHECK(resolve(ReferenceKind::Relative, at, 1, X64Fixture::kCall, 5) == X64Fixture::kFunc);
}

TEST_CASE("scan then resolve lands on the global, end to end", "[resolve]") {
    X64Fixture f;
    // Find the mov by signature the way a reader would, then resolve its match.
    const auto p = parse("48 8B 05 ?? ?? ?? ??");
    REQUIRE(p);
    const auto hits = scanReader(f.memory, f.memory.base(), f.memory.size(), *p);
    REQUIRE(hits.size() == 1);
    const std::uint64_t matchVa = hits[0];
    CHECK(matchVa == X64Fixture::kFunc);
    const std::uint64_t resolved =
        test::resolveAt(f.memory, ReferenceKind::RipRelative, matchVa, /*fieldOffset*/ 3, /*instrLen*/ 7);
    CHECK(resolved == X64Fixture::kGlobal);
}

TEST_CASE("[rip+disp] read follows the operand and reads the pointer there", "[resolve]") {
    X64Fixture f;
    const std::uint8_t* at = f.memory.bytes().data() + (X64Fixture::kFunc - X64Fixture::kBase);
    const auto value = readRipRelative(f.memory, at, /*fieldOffset*/ 3, X64Fixture::kFunc, /*instrLen*/ 7, /*pointerSize*/ 8);
    REQUIRE(value);
    CHECK(*value == 0xCAFEF00DDEADBEEFull);
}

TEST_CASE("absolute 32- and 64-bit fields are read straight from the match", "[resolve]") {
    // 68 <imm32>            push 0x00401234    (Absolute32, field at 1)
    // 48 B8 <imm64>         mov rax, imm64     (Absolute64, field at 2)
    std::vector<std::uint8_t> code = {0x68, 0x34, 0x12, 0x40, 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x0D, 0xF0, 0xFE, 0xCA};
    const std::uint8_t* at = code.data();
    CHECK(resolve(ReferenceKind::Absolute32, at, 1, 0, 0) == 0x00401234u);
    CHECK(resolve(ReferenceKind::Absolute64, at + 5, 2, 0, 0) == 0xCAFEF00DDEADBEEFull);
}

TEST_CASE("ReferenceKind::None returns the match address unchanged", "[resolve]") {
    std::vector<std::uint8_t> code = {0x90};
    CHECK(resolve(ReferenceKind::None, code.data(), 0, 0x1234, 1) == 0x1234u);
}
