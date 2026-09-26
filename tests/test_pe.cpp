#include "sigscan/sigscan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace sigscan;

namespace {

void put16(std::vector<std::uint8_t>& v, std::size_t at, std::uint16_t x) {
    v[at] = static_cast<std::uint8_t>(x);
    v[at + 1] = static_cast<std::uint8_t>(x >> 8);
}
void put32(std::vector<std::uint8_t>& v, std::size_t at, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}
void put64(std::vector<std::uint8_t>& v, std::size_t at, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(x >> (8 * i));
    }
}

// Builds a minimal but well-formed PE32+ image: DOS stub, PE signature, COFF
// and optional headers, and one ".text" section whose raw data holds a couple
// of recognizable byte runs.
std::vector<std::uint8_t> buildPe() {
    constexpr std::size_t kPeOff = 0x80;
    constexpr std::uint16_t kOptSize = 0xF0;
    const std::size_t optOff = kPeOff + 4 + 20;
    const std::size_t secOff = optOff + kOptSize;
    constexpr std::uint32_t kSizeOfHeaders = 0x400;
    constexpr std::uint32_t kTextRva = 0x1000;
    constexpr std::uint32_t kTextRaw = 0x400;
    constexpr std::uint32_t kTextSize = 0x200;

    std::vector<std::uint8_t> v(kTextRaw + kTextSize, 0);
    v[0] = 'M';
    v[1] = 'Z';
    put32(v, 0x3C, kPeOff);
    v[kPeOff] = 'P';
    v[kPeOff + 1] = 'E';

    std::uint8_t* coff = v.data() + kPeOff + 4;
    put16(v, kPeOff + 4 + 0, 0x8664);   // machine x64
    put16(v, kPeOff + 4 + 2, 1);        // one section
    put16(v, kPeOff + 4 + 16, kOptSize);// SizeOfOptionalHeader
    (void)coff;

    put16(v, optOff + 0, 0x20b);              // PE32+
    put64(v, optOff + 24, 0x140000000ull);    // ImageBase
    put32(v, optOff + 60, kSizeOfHeaders);    // SizeOfHeaders

    std::memcpy(v.data() + secOff, ".text\0\0\0", 8);
    put32(v, secOff + 8, kTextSize);   // VirtualSize
    put32(v, secOff + 12, kTextRva);   // VirtualAddress
    put32(v, secOff + 16, kTextSize);  // SizeOfRawData
    put32(v, secOff + 20, kTextRaw);   // PointerToRawData

    // A run in the headers (offset 0x100, maps 1:1 to RVA 0x100).
    const std::uint8_t hdrNeedle[] = {0x5A, 0x5B, 0x5C, 0x5D};
    std::memcpy(v.data() + 0x100, hdrNeedle, sizeof hdrNeedle);
    // A run in .text at file offset 0x410 -> RVA 0x1000 + (0x410 - 0x400) = 0x1010.
    const std::uint8_t textNeedle[] = {0x48, 0x8B, 0x05, 0xEF, 0xBE, 0xAD, 0xDE};
    std::memcpy(v.data() + 0x410, textNeedle, sizeof textNeedle);
    return v;
}

std::string writeTemp(const std::vector<std::uint8_t>& bytes) {
    const auto path = std::filesystem::temp_directory_path() / "sigscan_test_fixture.exe";
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.close();
    return path.string();
}

} // namespace

TEST_CASE("scanPeFile maps a .text match to the right RVA and file offset", "[pe]") {
    const std::string path = writeTemp(buildPe());
    const auto p = parse("48 8B 05 ?? ?? ?? ??");
    REQUIRE(p);
    const PeScanResult r = scanPeFile(path, *p);
    REQUIRE(r.ok());
    CHECK(r.info.is64);
    REQUIRE(r.info.sections.size() == 1);
    CHECK(r.info.sections[0].name == ".text");

    REQUIRE(r.matches.size() == 1);
    CHECK(r.matches[0].fileOffset == 0x410);
    REQUIRE(r.matches[0].rva.has_value());
    CHECK(*r.matches[0].rva == 0x1010);

    std::filesystem::remove(path);
}

TEST_CASE("scanPeFile maps a header match 1:1 and honors firstOnly", "[pe]") {
    const std::string path = writeTemp(buildPe());
    const auto p = parse("5A 5B 5C 5D");
    REQUIRE(p);
    const PeScanResult r = scanPeFile(path, *p);
    REQUIRE(r.ok());
    REQUIRE(r.matches.size() == 1);
    CHECK(r.matches[0].fileOffset == 0x100);
    REQUIRE(r.matches[0].rva.has_value());
    CHECK(*r.matches[0].rva == 0x100); // headers map 1:1

    std::filesystem::remove(path);
}

TEST_CASE("a file that is not a PE is reported, not scanned", "[pe]") {
    const auto path = std::filesystem::temp_directory_path() / "sigscan_not_a_pe.bin";
    {
        std::ofstream out(path, std::ios::binary);
        const char junk[] = "this is not an executable at all";
        out.write(junk, sizeof junk);
    }
    const auto p = parse("48 8B 05");
    REQUIRE(p);
    const PeScanResult r = scanPeFile(path.string(), *p);
    CHECK_FALSE(r.ok());
    CHECK(r.error.find("not a PE") != std::string::npos);
    std::filesystem::remove(path);
}

TEST_CASE("a missing file is reported", "[pe]") {
    const auto p = parse("90");
    REQUIRE(p);
    const PeScanResult r = scanPeFile("C:/no/such/file/at/all.exe", *p);
    CHECK_FALSE(r.ok());
}
