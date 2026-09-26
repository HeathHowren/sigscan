#include "FakeMemory.h"

#include "sigscan/sigscan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <span>
#include <vector>

using namespace sigscan;

namespace {

// A brute-force scalar reference, independent of the library's SIMD paths, so
// the accelerated result can be checked against it.
std::vector<std::size_t> bruteForce(const std::vector<std::uint8_t>& h, const Pattern& p) {
    std::vector<std::size_t> out;
    if (p.empty() || h.size() < p.size()) {
        return out;
    }
    for (std::size_t pos = 0; pos + p.size() <= h.size(); ++pos) {
        bool ok = true;
        for (std::size_t i = 0; i < p.size() && ok; ++i) {
            const std::uint8_t m = p.mask[i];
            ok = static_cast<std::uint8_t>(h[pos + i] & m) == static_cast<std::uint8_t>(p.bytes[i] & m);
        }
        if (ok) {
            out.push_back(pos);
        }
    }
    return out;
}

std::vector<std::uint8_t> filler(std::size_t n, std::uint32_t seed = 0x2468ACE0u) {
    std::vector<std::uint8_t> v(n);
    std::uint32_t s = seed;
    for (auto& b : v) {
        s = s * 1664525u + 1013904223u;
        b = static_cast<std::uint8_t>(s >> 24);
    }
    return v;
}

} // namespace

TEST_CASE("find returns the first match and findAll returns every match", "[scan]") {
    std::vector<std::uint8_t> h = {0x00, 0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0x90, 0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD};
    const auto p = parse("48 8B 05 ?? ?? ?? ??");
    REQUIRE(p);
    std::span<const std::uint8_t> sp(h.data(), h.size());

    const auto first = find(sp, *p);
    REQUIRE(first);
    CHECK(*first == 1);

    const auto all = findAll(sp, *p);
    REQUIRE(all.size() == 2);
    CHECK(all[0] == 1);
    CHECK(all[1] == 9);

    const auto capped = findAll(sp, *p, 1);
    CHECK(capped.size() == 1);
}

TEST_CASE("nothing is found when the pattern is not present", "[scan]") {
    const auto h = filler(4096);
    const auto p = parse("DE AD BE EF CA FE BA BE");
    REQUIRE(p);
    CHECK_FALSE(find(std::span<const std::uint8_t>(h.data(), h.size()), *p));
    CHECK(findAll(std::span<const std::uint8_t>(h.data(), h.size()), *p).empty());
}

TEST_CASE("the active backend agrees with brute force across sizes and anchors", "[scan]") {
    INFO("backend: " << backendName(activeBackend()));
    // A needle long enough to cross a 16- and a 32-byte SIMD lane, planted at
    // many offsets in filler large enough for several vector iterations.
    for (std::size_t needleLen : {1u, 3u, 7u, 16u, 20u, 33u}) {
        for (std::size_t planted : {0u, 15u, 16u, 31u, 63u, 1000u, 4095u}) {
            auto h = filler(8192, 0x99u + static_cast<std::uint32_t>(needleLen));
            std::vector<std::uint8_t> needle(needleLen);
            for (std::size_t i = 0; i < needleLen; ++i) {
                needle[i] = static_cast<std::uint8_t>(0xC0 + i); // bytes unlikely to occur in filler
            }
            if (planted + needleLen <= h.size()) {
                std::copy(needle.begin(), needle.end(), h.begin() + static_cast<std::ptrdiff_t>(planted));
            }
            Pattern p;
            for (std::uint8_t b : needle) {
                p.append(b, 0xFF);
            }
            const auto got = findAll(std::span<const std::uint8_t>(h.data(), h.size()), p);
            const auto ref = bruteForce(h, p);
            INFO("needleLen=" << needleLen << " planted=" << planted);
            CHECK(got == ref);
        }
    }
}

TEST_CASE("a wildcard in the anchor position falls back to scalar and still matches", "[scan]") {
    // Leading wildcard: no fixed byte until index 1, so the anchor is not byte 0.
    std::vector<std::uint8_t> h = {0x11, 0xE8, 0x01, 0x02, 0x03, 0x04, 0x55};
    const auto p = parse("?? E8 ?? ?? ?? ??");
    REQUIRE(p);
    const auto all = findAll(std::span<const std::uint8_t>(h.data(), h.size()), *p);
    REQUIRE(all.size() == 1);
    CHECK(all[0] == 0);
}

TEST_CASE("an all-wildcard pattern matches at every valid position", "[scan]") {
    std::vector<std::uint8_t> h = {1, 2, 3, 4, 5};
    const auto p = parse("?? ?? ??");
    REQUIRE(p);
    const auto all = findAll(std::span<const std::uint8_t>(h.data(), h.size()), *p);
    CHECK(all.size() == 3); // positions 0, 1, 2
}

TEST_CASE("nibble masks match on one nibble only", "[scan]") {
    std::vector<std::uint8_t> h = {0x40, 0x4A, 0x5A, 0x4F};
    const auto p = parse("4?"); // high nibble 4
    REQUIRE(p);
    const auto all = findAll(std::span<const std::uint8_t>(h.data(), h.size()), *p);
    REQUIRE(all.size() == 3);
    CHECK(all == std::vector<std::size_t>{0, 1, 3});
}

// --- scanReader: page and window boundaries, unreadable pages ---------------

TEST_CASE("scanReader finds a match straddling a page boundary", "[scan][reader]") {
    test::FakeMemory mem(0x140000000, 0x1000, /*pageSize*/ 0x100);
    const std::uint64_t base = mem.base();
    // 8-byte needle straddling the 0x100 page boundary at offset 0xFC..0x103.
    mem.write(base + 0xFC, {0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8});
    const auto p = parse("C1 C2 C3 C4 C5 C6 C7 C8");
    REQUIRE(p);
    const auto hits = scanReader(mem, base, mem.size(), *p);
    REQUIRE(hits.size() == 1);
    CHECK(hits[0] == base + 0xFC);
}

TEST_CASE("scanReader stitches a match across its own window flush", "[scan][reader]") {
    test::FakeMemory mem(0x400000, 0x1000, /*pageSize*/ 0x100);
    const std::uint64_t base = mem.base();
    // Force flushing every ~512 bytes; plant a needle straddling offset 0x1FE
    // so it crosses the retained-tail boundary between two windows.
    mem.write(base + 0x1FE, {0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6});
    const auto p = parse("E1 E2 E3 E4 E5 E6");
    REQUIRE(p);
    const auto hits = scanReader(mem, base, mem.size(), *p, /*firstOnly*/ false, /*windowBytes*/ 0x200);
    REQUIRE(hits.size() == 1);
    CHECK(hits[0] == base + 0x1FE);
}

TEST_CASE("scanReader firstOnly stops at the first match", "[scan][reader]") {
    test::FakeMemory mem(0x400000, 0x1000, 0x100);
    const std::uint64_t base = mem.base();
    mem.write(base + 0x40, {0xAB, 0xCD, 0xEF, 0x01});
    mem.write(base + 0x340, {0xAB, 0xCD, 0xEF, 0x01});
    const auto p = parse("AB CD EF 01");
    REQUIRE(p);

    const auto first = scanReader(mem, base, mem.size(), *p, /*firstOnly*/ true);
    REQUIRE(first.size() == 1);
    CHECK(first[0] == base + 0x40);

    const auto all = scanReader(mem, base, mem.size(), *p);
    CHECK(all.size() == 2);
}

TEST_CASE("scanReader skips an unreadable page and never matches across the gap", "[scan][reader]") {
    test::FakeMemory mem(0x400000, 0x1000, 0x100);
    const std::uint64_t base = mem.base();
    // A readable match after an unreadable page is found.
    mem.write(base + 0x520, {0x7A, 0x7B, 0x7C, 0x7D});
    // A "match" that would straddle into the unreadable page must not be found.
    mem.write(base + 0x2FE, {0x11, 0x22, 0x33, 0x44});
    mem.markUnreadable(base + 0x300, 0x100);
    const auto found = parse("7A 7B 7C 7D");
    const auto straddle = parse("11 22 33 44");
    REQUIRE(found);
    REQUIRE(straddle);

    const auto a = scanReader(mem, base, mem.size(), *found);
    REQUIRE(a.size() == 1);
    CHECK(a[0] == base + 0x520);

    const auto b = scanReader(mem, base, mem.size(), *straddle);
    CHECK(b.empty()); // its last two bytes are in the unreadable page
}
