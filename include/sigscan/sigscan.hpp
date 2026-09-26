// sigscan: parse a byte signature in any common form and find it.
//
// A single-header C++20 library with no third-party dependencies. It is the
// read side of Signature Lab (https://github.com/HeathHowren/Signature-Lab):
// the forms Signature Lab writes are the forms this parses, and the resolve
// helpers here mirror the resolve line Signature Lab prints for a reference
// signature.
//
// Written by Heath Howren (Cyborg Elf) of Game Reversal Club. MIT License.
//
// Overview:
//   sigscan::parse(text)            -> ParseResult (Pattern or an error string)
//   sigscan::format(pattern, form)  -> a signature in one of the output forms
//   sigscan::find / findAll(span)   -> first or all matches in a byte span
//   sigscan::scanReader(...)        -> matches in a page-readable region, so a
//                                      match spanning a page boundary is found
//   sigscan::scanPeFile(path)       -> matches in an on-disk PE, RVA + offset
//   sigscan::scanProcessModule(...) -> matches in a live module (Windows)
//   sigscan::resolve(...)           -> a match back to the address it refers to
//
// The scanner uses an SSE2 anchor search with an AVX2 path when the CPU has it
// and a scalar fallback everywhere else. activeBackend() reports which is live.

#ifndef SIGSCAN_HPP
#define SIGSCAN_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#define SIGSCAN_X86 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#else
#define SIGSCAN_X86 0
#endif

namespace sigscan {

// ---------------------------------------------------------------------------
// Pattern
//
// mask semantics, the same as Signature Lab's:
//   0xFF  compare the whole byte
//   0x00  wildcard, compare nothing
//   0xF0  compare the high nibble only ("4?")
//   0x0F  compare the low nibble only  ("?4")
// A byte b matches pattern byte p under mask m when (b & m) == (p & m), which
// is one formula for every mask value above.
// ---------------------------------------------------------------------------

struct Pattern {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> mask;

    [[nodiscard]] std::size_t size() const { return bytes.size(); }
    [[nodiscard]] bool empty() const { return bytes.empty(); }
    [[nodiscard]] bool isWildcard(std::size_t i) const { return mask[i] == 0; }

    [[nodiscard]] std::size_t wildcardCount() const {
        std::size_t n = 0;
        for (std::uint8_t m : mask) {
            if (m != 0xFF) {
                ++n;
            }
        }
        return n;
    }
    [[nodiscard]] std::size_t fixedCount() const { return size() - wildcardCount(); }

    [[nodiscard]] bool hasNibbleMask() const {
        for (std::uint8_t m : mask) {
            if (m != 0xFF && m != 0x00) {
                return true;
            }
        }
        return false;
    }

    void append(std::uint8_t byte, std::uint8_t maskByte) {
        bytes.push_back(byte);
        mask.push_back(maskByte);
    }

    [[nodiscard]] Pattern prefix(std::size_t count) const {
        Pattern out;
        if (count > size()) {
            count = size();
        }
        out.bytes.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count));
        out.mask.assign(mask.begin(), mask.begin() + static_cast<std::ptrdiff_t>(count));
        return out;
    }
};

// The output forms Signature Lab writes. The x64dbg and IDA forms differ only
// in how a wildcard is spelled: x64dbg treats a lone '?' as one nibble, so a
// whole wildcard byte is '??' there, whereas IDA writes a single '?'.
enum class Format : std::uint8_t {
    X64dbg,     // 48 8B 05 ?? ?? ?? ??
    Ida,        // 48 8B 05 ? ? ? ?
    CodeMask,   // "\x48\x8B\x05\x00\x00\x00\x00" and "xxx????"
    CppArray,   // const unsigned char sig[] = { ... }; const char mask[] = "...";
    PointerLab, // aobscanmodule(INJECT, module.exe, 48 8B 05 ?? ?? ?? ??)
};

inline constexpr Format kAllFormats[] = {Format::X64dbg, Format::Ida, Format::CodeMask, Format::CppArray, Format::PointerLab};

[[nodiscard]] inline const char* formatName(Format form) {
    switch (form) {
    case Format::X64dbg:
        return "x64dbg";
    case Format::Ida:
        return "IDA";
    case Format::CodeMask:
        return "code+mask";
    case Format::CppArray:
        return "C++ array";
    case Format::PointerLab:
        return "Pointer Lab";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Parsing internals
// ---------------------------------------------------------------------------

namespace detail {

constexpr char kHexDigits[] = "0123456789ABCDEF";

inline int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

inline void appendHex(std::string& out, std::uint8_t byte) {
    out += kHexDigits[byte >> 4];
    out += kHexDigits[byte & 0x0F];
}

inline bool isSeparator(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',';
}

inline char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

} // namespace detail

// The result of parse(). On success `pattern` holds the parsed pattern and
// `error` is empty. On failure `error` says what was wrong, so a malformed
// pattern is reported rather than silently treated as "no match".
struct ParseResult {
    Pattern pattern;
    std::string error;

    [[nodiscard]] bool ok() const { return error.empty(); }
    explicit operator bool() const { return ok(); }
    const Pattern* operator->() const { return &pattern; }
    const Pattern& operator*() const { return pattern; }
};

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

namespace detail {

inline std::string spellX64dbg(const Pattern& p) {
    std::string out;
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        const std::uint8_t m = p.mask[i];
        const std::uint8_t b = p.bytes[i];
        if (m == 0xFF) {
            appendHex(out, b);
        } else if (m == 0xF0) {
            out += kHexDigits[b >> 4];
            out += '?';
        } else if (m == 0x0F) {
            out += '?';
            out += kHexDigits[b & 0x0F];
        } else {
            out += "??";
        }
    }
    return out;
}

inline std::string spellIda(const Pattern& p) {
    std::string out;
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        if (p.mask[i] == 0xFF) {
            appendHex(out, p.bytes[i]);
        } else {
            out += '?';
        }
    }
    return out;
}

inline std::string spellMaskString(const Pattern& p) {
    std::string out;
    out.reserve(p.size());
    for (std::size_t i = 0; i < p.size(); ++i) {
        out += p.mask[i] == 0xFF ? 'x' : '?';
    }
    return out;
}

inline std::string spellCodeMask(const Pattern& p) {
    std::string out = "\"";
    for (std::size_t i = 0; i < p.size(); ++i) {
        out += "\\x";
        appendHex(out, p.mask[i] == 0xFF ? p.bytes[i] : std::uint8_t{0});
    }
    out += "\"\n\"";
    out += spellMaskString(p);
    out += '"';
    return out;
}

inline std::string spellCppArray(const Pattern& p) {
    std::string out = "const unsigned char sig[] = { ";
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += "0x";
        appendHex(out, p.mask[i] == 0xFF ? p.bytes[i] : std::uint8_t{0});
    }
    out += " };\nconst char mask[] = \"";
    out += spellMaskString(p);
    out += "\";";
    return out;
}

inline std::string spellPointerLab(const Pattern& p, std::string_view moduleName, std::string_view symbol) {
    std::string out = "aobscanmodule(";
    out += symbol.empty() ? std::string_view{"INJECT"} : symbol;
    out += ", ";
    out += moduleName.empty() ? std::string_view{"module.exe"} : moduleName;
    out += ", ";
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        if (p.mask[i] == 0xFF) {
            appendHex(out, p.bytes[i]);
        } else {
            out += "??";
        }
    }
    out += ')';
    return out;
}

} // namespace detail

// Renders a pattern in one form. `moduleName` and `symbol` are used by the
// Pointer Lab form only; a missing module name renders as "module.exe".
[[nodiscard]] inline std::string format(const Pattern& pattern, Format form, std::string_view moduleName = {},
                                        std::string_view symbol = "INJECT") {
    switch (form) {
    case Format::X64dbg:
        return detail::spellX64dbg(pattern);
    case Format::Ida:
        return detail::spellIda(pattern);
    case Format::CodeMask:
        return detail::spellCodeMask(pattern);
    case Format::CppArray:
        return detail::spellCppArray(pattern);
    case Format::PointerLab:
        return detail::spellPointerLab(pattern, moduleName, symbol);
    }
    return detail::spellX64dbg(pattern);
}

// Formats raw bytes as "48 8B 05".
[[nodiscard]] inline std::string hexBytes(const std::uint8_t* data, std::size_t size) {
    std::string out;
    out.reserve(size * 3);
    for (std::size_t i = 0; i < size; ++i) {
        if (i != 0) {
            out += ' ';
        }
        detail::appendHex(out, data[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

namespace detail {

// Hex pairs with '?' or '??' wildcards, '4?' nibbles, optionally no separators.
inline ParseResult parseHex(std::string_view text) {
    ParseResult r;
    Pattern& p = r.pattern;
    std::size_t i = 0;
    const std::size_t n = text.size();
    while (i < n) {
        const char c = text[i];
        if (isSeparator(c)) {
            ++i;
            continue;
        }
        const bool hasNext = i + 1 < n;
        const char next = hasNext ? text[i + 1] : '\0';
        if (c == '?') {
            if (hasNext && next == '?') {
                p.append(0, 0x00);
                i += 2;
            } else if (hasNext && hexValue(next) >= 0) {
                p.append(static_cast<std::uint8_t>(hexValue(next)), 0x0F);
                i += 2;
            } else {
                p.append(0, 0x00);
                i += 1;
            }
            continue;
        }
        const int hi = hexValue(c);
        if (hi < 0) {
            r.error = std::string("unexpected character '") + c + "' in the pattern";
            r.pattern = Pattern{};
            return r;
        }
        if (hasNext && hexValue(next) >= 0) {
            p.append(static_cast<std::uint8_t>((hi << 4) | hexValue(next)), 0xFF);
            i += 2;
        } else if (hasNext && next == '?') {
            p.append(static_cast<std::uint8_t>(hi << 4), 0xF0);
            i += 2;
        } else {
            r.error = "a lone hex digit is not a whole byte";
            r.pattern = Pattern{};
            return r;
        }
    }
    if (p.empty()) {
        r.error = "the pattern is empty";
    }
    return r;
}

// Finds the mask that goes with `count` bytes in text whose byte tokens have
// been blanked to spaces: a run of 'x'/'?' or a "0b0110" bitmask (1 = compare)
// of exactly `count` characters. Reports whether any mask run was present, so a
// mask of the wrong length can be treated as an error, not ignored.
struct MaskSearch {
    bool present = false;
    std::optional<std::vector<std::uint8_t>> mask;
};

inline MaskSearch findMask(std::string_view blanked, std::size_t count) {
    MaskSearch search;
    std::size_t i = 0;
    const std::size_t n = blanked.size();
    while (i < n) {
        std::vector<std::uint8_t> run;
        std::size_t j = i;
        if (blanked[i] == '0' && i + 1 < n && (blanked[i + 1] == 'b' || blanked[i + 1] == 'B')) {
            j = i + 2;
            while (j < n && (blanked[j] == '0' || blanked[j] == '1')) {
                run.push_back(blanked[j] == '1' ? 0xFF : 0x00);
                ++j;
            }
        } else if (blanked[i] == 'x' || blanked[i] == '?') {
            while (j < n && (blanked[j] == 'x' || blanked[j] == '?')) {
                run.push_back(blanked[j] == 'x' ? 0xFF : 0x00);
                ++j;
            }
        }
        if (run.size() >= 2) {
            search.present = true;
            if (run.size() == count && !search.mask) {
                search.mask = std::move(run);
            }
        }
        i = j > i ? j : i + 1;
    }
    return search;
}

// Applies the mask found in the text: the right-length one if there is one,
// every byte compared if there is none, failure if there is only a wrong one.
inline bool applyMask(Pattern& p, std::string_view blanked, std::string& error) {
    MaskSearch search = findMask(blanked, p.size());
    if (search.mask) {
        p.mask = std::move(*search.mask);
        return true;
    }
    if (search.present) {
        error = "the mask length does not match the number of bytes (" + std::to_string(p.size()) + ")";
        return false;
    }
    return true;
}

// "\x48\x8B..." optionally followed by an "xxx????" mask.
inline ParseResult parseCodeStyle(std::string_view text) {
    ParseResult r;
    Pattern& p = r.pattern;
    std::string blanked(text);
    for (std::size_t i = 0; i + 3 < text.size(); ++i) {
        if (text[i] == '\\' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            const int hi = hexValue(text[i + 2]);
            const int lo = hexValue(text[i + 3]);
            if (hi < 0 || lo < 0) {
                r.error = "a \\x escape is not followed by two hex digits";
                r.pattern = Pattern{};
                return r;
            }
            p.append(static_cast<std::uint8_t>((hi << 4) | lo), 0xFF);
            blanked[i] = blanked[i + 1] = blanked[i + 2] = blanked[i + 3] = ' ';
            i += 3;
        }
    }
    if (p.empty()) {
        r.error = "no \\x bytes were found";
        return r;
    }
    if (!applyMask(p, blanked, r.error)) {
        r.pattern = Pattern{};
    }
    return r;
}

// "{ 0x48, 0x8B, ... }" optionally followed by an "xxx????" mask or a bitmask.
inline ParseResult parseCArray(std::string_view text) {
    ParseResult r;
    Pattern& p = r.pattern;
    std::string blanked(text);
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X') && hexValue(text[i + 2]) >= 0) {
            int value = hexValue(text[i + 2]);
            std::size_t end = i + 3;
            if (end < text.size() && hexValue(text[end]) >= 0) {
                value = (value << 4) | hexValue(text[end]);
                ++end;
            }
            if (end < text.size() && hexValue(text[end]) >= 0) {
                r.error = "0x-value with more than two hex digits is not a byte";
                r.pattern = Pattern{};
                return r;
            }
            p.append(static_cast<std::uint8_t>(value), 0xFF);
            for (std::size_t k = i; k < end; ++k) {
                blanked[k] = ' ';
            }
            i = end - 1;
        }
    }
    if (p.empty()) {
        r.error = "no 0x bytes were found";
        return r;
    }
    if (!applyMask(p, blanked, r.error)) {
        r.pattern = Pattern{};
    }
    return r;
}

} // namespace detail

// Parses any of the forms format() produces, plus the common variations: a
// lone '?' or '??' per wildcard byte, '4?' nibble wildcards, no separators at
// all ("488B??24"), a code-style string with or without its mask on the next
// line, a C array with an "xxx????" mask or a "0b1110000" bitmask, and a
// Cheat Engine / Pointer Lab aobscanmodule(...) line. Reports a reason for text
// that is not a pattern, including a mask whose length does not fit the bytes.
[[nodiscard]] inline ParseResult parse(std::string_view text) {
    while (!text.empty() && detail::isSeparator(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && detail::isSeparator(text.back())) {
        text.remove_suffix(1);
    }
    if (text.empty()) {
        ParseResult r;
        r.error = "the pattern is empty";
        return r;
    }
    if (text.find("\\x") != std::string_view::npos || text.find("\\X") != std::string_view::npos) {
        return detail::parseCodeStyle(text);
    }
    // A Cheat Engine / Pointer Lab line: the pattern is the last argument.
    if (text.rfind("aobscan", 0) == 0) {
        const auto open = text.find('(');
        const auto close = text.rfind(')');
        if (open == std::string_view::npos || close == std::string_view::npos || close <= open) {
            ParseResult r;
            r.error = "aobscanmodule(...) is missing its parentheses";
            return r;
        }
        std::string_view inner = text.substr(open + 1, close - open - 1);
        const auto lastComma = inner.rfind(',');
        if (lastComma != std::string_view::npos) {
            inner = inner.substr(lastComma + 1);
        }
        return detail::parseHex(inner);
    }
    if (text.find("0x") != std::string_view::npos || text.find("0X") != std::string_view::npos) {
        return detail::parseCArray(text);
    }
    return detail::parseHex(text);
}

// ---------------------------------------------------------------------------
// Scanning: scalar, SSE2 and AVX2 anchor search over a contiguous span
// ---------------------------------------------------------------------------

enum class Backend : std::uint8_t { Scalar, Sse2, Avx2 };

[[nodiscard]] inline const char* backendName(Backend b) {
    switch (b) {
    case Backend::Scalar:
        return "scalar";
    case Backend::Sse2:
        return "SSE2";
    case Backend::Avx2:
        return "AVX2";
    }
    return "scalar";
}

namespace detail {

inline bool cpuHasAvx2() {
#if SIGSCAN_X86 && defined(_MSC_VER)
    int info1[4] = {0, 0, 0, 0};
    __cpuid(info1, 1);
    const bool osxsave = (info1[2] & (1 << 27)) != 0;
    const bool avx = (info1[2] & (1 << 28)) != 0;
    if (!osxsave || !avx) {
        return false;
    }
    const unsigned long long xcr0 = _xgetbv(0);
    if ((xcr0 & 0x6) != 0x6) { // XMM and YMM state enabled by the OS
        return false;
    }
    int info7[4] = {0, 0, 0, 0};
    __cpuidex(info7, 7, 0);
    return (info7[1] & (1 << 5)) != 0; // AVX2
#elif SIGSCAN_X86 && (defined(__GNUC__) || defined(__clang__))
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

inline Backend detectBackend() {
#if SIGSCAN_X86
    if (cpuHasAvx2()) {
        return Backend::Avx2;
    }
    return Backend::Sse2; // baseline on every x64, and MSVC's default on x86
#else
    return Backend::Scalar;
#endif
}

// One byte b matches pattern byte p under mask m.
inline bool byteMatches(std::uint8_t b, std::uint8_t p, std::uint8_t m) {
    return static_cast<std::uint8_t>(b & m) == static_cast<std::uint8_t>(p & m);
}

inline bool matchAt(const std::uint8_t* h, std::size_t hlen, std::size_t pos, const Pattern& pat) {
    const std::size_t plen = pat.size();
    if (pos + plen > hlen) {
        return false;
    }
    for (std::size_t i = 0; i < plen; ++i) {
        const std::uint8_t m = pat.mask[i];
        if (m == 0xFF) {
            if (h[pos + i] != pat.bytes[i]) {
                return false;
            }
        } else if (m != 0x00) {
            if (!byteMatches(h[pos + i], pat.bytes[i], m)) {
                return false;
            }
        }
    }
    return true;
}

// Index of the first fully-fixed byte (mask 0xFF), used as the SIMD anchor. No
// fixed byte (an all-wildcard or nibble-only pattern) means the anchor search
// cannot help, so the scalar path handles it.
inline std::optional<std::size_t> anchorIndex(const Pattern& pat) {
    for (std::size_t i = 0; i < pat.size(); ++i) {
        if (pat.mask[i] == 0xFF) {
            return i;
        }
    }
    return std::nullopt;
}

inline std::optional<std::size_t> scanScalar(const std::uint8_t* h, std::size_t hlen, const Pattern& pat, std::size_t from) {
    const std::size_t plen = pat.size();
    if (plen == 0 || hlen < plen) {
        return std::nullopt;
    }
    const std::size_t last = hlen - plen;
    for (std::size_t pos = from; pos <= last; ++pos) {
        if (matchAt(h, hlen, pos, pat)) {
            return pos;
        }
    }
    return std::nullopt;
}

#if SIGSCAN_X86
inline std::optional<std::size_t> scanSse2(const std::uint8_t* h, std::size_t hlen, const Pattern& pat, std::size_t from,
                                           std::size_t anchor) {
    const std::size_t plen = pat.size();
    const std::size_t last = hlen - plen;
    const __m128i needle = _mm_set1_epi8(static_cast<char>(pat.bytes[anchor]));
    std::size_t pos = from;
    // A 16-byte load at pos+anchor must stay inside the buffer.
    while (pos <= last && pos + anchor + 16 <= hlen) {
        const __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(h + pos + anchor));
        unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(block, needle)));
        while (mask != 0) {
            const unsigned bit = static_cast<unsigned>(mask & (0u - mask)); // lowest set bit
            std::size_t lane = 0;
            for (unsigned t = bit; t > 1; t >>= 1) {
                ++lane;
            }
            const std::size_t cand = pos + lane;
            if (cand <= last && matchAt(h, hlen, cand, pat)) {
                return cand;
            }
            mask &= mask - 1;
        }
        pos += 16;
    }
    return scanScalar(h, hlen, pat, pos);
}

inline std::optional<std::size_t> scanAvx2(const std::uint8_t* h, std::size_t hlen, const Pattern& pat, std::size_t from,
                                           std::size_t anchor) {
    const std::size_t plen = pat.size();
    const std::size_t last = hlen - plen;
    const __m256i needle = _mm256_set1_epi8(static_cast<char>(pat.bytes[anchor]));
    std::size_t pos = from;
    while (pos <= last && pos + anchor + 32 <= hlen) {
        const __m256i block = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(h + pos + anchor));
        unsigned mask = static_cast<unsigned>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(block, needle)));
        while (mask != 0) {
            unsigned long lane = 0;
#if defined(_MSC_VER)
            _BitScanForward(&lane, mask);
#else
            lane = static_cast<unsigned long>(__builtin_ctz(mask));
#endif
            const std::size_t cand = pos + lane;
            if (cand <= last && matchAt(h, hlen, cand, pat)) {
                return cand;
            }
            mask &= mask - 1;
        }
        pos += 32;
    }
    return scanScalar(h, hlen, pat, pos);
}
#endif // SIGSCAN_X86

} // namespace detail

// The backend chosen at first use, cached for the life of the process.
[[nodiscard]] inline Backend activeBackend() {
    static const Backend b = detail::detectBackend();
    return b;
}

// First match at or after `from`, or nothing.
[[nodiscard]] inline std::optional<std::size_t> findFrom(std::span<const std::uint8_t> haystack, const Pattern& pattern,
                                                         std::size_t from = 0) {
    const std::uint8_t* h = haystack.data();
    const std::size_t hlen = haystack.size();
    const std::size_t plen = pattern.size();
    if (plen == 0 || hlen < plen || from > hlen - plen) {
        return std::nullopt;
    }
    const auto anchor = detail::anchorIndex(pattern);
#if SIGSCAN_X86
    if (anchor) {
        switch (activeBackend()) {
        case Backend::Avx2:
            return detail::scanAvx2(h, hlen, pattern, from, *anchor);
        case Backend::Sse2:
            return detail::scanSse2(h, hlen, pattern, from, *anchor);
        case Backend::Scalar:
            break;
        }
    }
#else
    (void)anchor;
#endif
    return detail::scanScalar(h, hlen, pattern, from);
}

// First match in the span, or nothing.
[[nodiscard]] inline std::optional<std::size_t> find(std::span<const std::uint8_t> haystack, const Pattern& pattern) {
    return findFrom(haystack, pattern, 0);
}

// Every match in the span, in order. `limit` of 0 means no limit.
[[nodiscard]] inline std::vector<std::size_t> findAll(std::span<const std::uint8_t> haystack, const Pattern& pattern,
                                                      std::size_t limit = 0) {
    std::vector<std::size_t> out;
    if (pattern.empty()) {
        return out;
    }
    std::size_t from = 0;
    while (auto pos = findFrom(haystack, pattern, from)) {
        out.push_back(*pos);
        if (limit != 0 && out.size() >= limit) {
            break;
        }
        from = *pos + 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Reading a region page by page (a live process, a memory-mapped image)
//
// scanReader reads the region in windows and carries a (pattern length - 1)
// byte tail between them, so a match that straddles a window or page boundary
// is found exactly once. An unreadable page is skipped and the scan goes on
// past it. No match can span a gap that cannot be read.
// ---------------------------------------------------------------------------

class MemoryReader {
public:
    virtual ~MemoryReader() = default;
    // Reads exactly `size` bytes at `address`, or returns false.
    [[nodiscard]] virtual bool read(std::uint64_t address, void* destination, std::size_t size) const = 0;
    [[nodiscard]] virtual std::uint64_t pageSize() const { return 0x1000; }
};

// Scans [base, base + size) through `reader`. Reported offsets are absolute
// addresses. `windowBytes` bounds how much is held in memory at once.
inline std::vector<std::uint64_t> scanReader(const MemoryReader& reader, std::uint64_t base, std::uint64_t size,
                                             const Pattern& pattern, bool firstOnly = false, std::size_t windowBytes = 1u << 16) {
    std::vector<std::uint64_t> out;
    const std::size_t plen = pattern.size();
    if (plen == 0 || size < plen) {
        return out;
    }
    std::uint64_t page = reader.pageSize();
    if (page == 0) {
        page = 0x1000;
    }
    if (windowBytes < plen * 2) {
        windowBytes = plen * 2;
    }

    std::vector<std::uint8_t> buf;
    std::uint64_t bufStart = base;
    std::uint64_t addr = base;
    const std::uint64_t end = base + size;
    std::vector<std::uint8_t> tmp;
    bool stop = false;

    // Scans the current buffer, emits absolute matches, and unless `keepTail`
    // keeps the last (plen - 1) bytes for the next window, drops the buffer.
    auto flush = [&](bool keepTail) {
        if (buf.size() >= plen) {
            std::span<const std::uint8_t> sp(buf.data(), buf.size());
            std::size_t from = 0;
            while (auto pos = findFrom(sp, pattern, from)) {
                out.push_back(bufStart + *pos);
                if (firstOnly) {
                    stop = true;
                    return;
                }
                from = *pos + 1;
            }
        }
        if (keepTail && buf.size() > plen - 1) {
            const std::size_t drop = buf.size() - (plen - 1);
            bufStart += drop;
            buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(drop));
        } else {
            buf.clear();
        }
    };

    while (addr < end && !stop) {
        const std::uint64_t chunk = std::min<std::uint64_t>(page - (addr % page), end - addr);
        tmp.resize(static_cast<std::size_t>(chunk));
        if (reader.read(addr, tmp.data(), static_cast<std::size_t>(chunk))) {
            buf.insert(buf.end(), tmp.begin(), tmp.end());
            addr += chunk;
            if (buf.size() >= windowBytes) {
                flush(true);
            }
        } else {
            // Unreadable page: scan what was read so far, then start fresh past it.
            flush(false);
            bufStart = addr + chunk;
            addr += chunk;
        }
    }
    if (!stop) {
        flush(false);
    }
    return out;
}

// ---------------------------------------------------------------------------
// PE files: map a file offset to an RVA and back, and scan an on-disk PE
// ---------------------------------------------------------------------------

struct PeSection {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0;
};

struct PeInfo {
    bool is64 = false;
    std::uint64_t imageBase = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::vector<PeSection> sections;

    // Maps a file offset to its RVA, or nothing if the offset is not backed by
    // a section or the headers.
    [[nodiscard]] std::optional<std::uint32_t> offsetToRva(std::uint64_t offset) const {
        for (const auto& s : sections) {
            if (s.rawSize != 0 && offset >= s.rawOffset && offset < static_cast<std::uint64_t>(s.rawOffset) + s.rawSize) {
                return static_cast<std::uint32_t>(s.virtualAddress + (offset - s.rawOffset));
            }
        }
        if (offset < sizeOfHeaders) {
            return static_cast<std::uint32_t>(offset); // headers are mapped 1:1
        }
        return std::nullopt;
    }
};

struct PeMatch {
    std::uint64_t fileOffset = 0;
    std::optional<std::uint32_t> rva; // nothing when the offset is in slack between sections
};

struct PeScanResult {
    PeInfo info;
    std::vector<PeMatch> matches;
    std::string error; // set when the file could not be read or is not a PE

    [[nodiscard]] bool ok() const { return error.empty(); }
};

namespace detail {

inline std::uint16_t rd16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}
inline std::uint32_t rd32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<std::uint32_t>(p[3]) << 24));
}
inline std::uint64_t rd64(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(rd32(p)) | (static_cast<std::uint64_t>(rd32(p + 4)) << 32);
}

// Parses the PE headers of an in-memory image. Returns nothing with a reason if
// the buffer is not a PE.
inline std::optional<PeInfo> parsePeHeaders(const std::vector<std::uint8_t>& img, std::string& error) {
    if (img.size() < 0x40 || img[0] != 'M' || img[1] != 'Z') {
        error = "not a PE file (no MZ header)";
        return std::nullopt;
    }
    const std::uint32_t peOff = rd32(img.data() + 0x3C);
    if (static_cast<std::uint64_t>(peOff) + 24 > img.size() || std::memcmp(img.data() + peOff, "PE\0\0", 4) != 0) {
        error = "not a PE file (no PE signature)";
        return std::nullopt;
    }
    const std::uint8_t* coff = img.data() + peOff + 4;
    const std::uint16_t numSections = rd16(coff + 2);
    const std::uint16_t optSize = rd16(coff + 16);
    const std::uint8_t* opt = coff + 20;
    if (opt + optSize > img.data() + img.size()) {
        error = "PE optional header runs past the end of the file";
        return std::nullopt;
    }
    PeInfo info;
    const std::uint16_t magic = rd16(opt);
    info.is64 = magic == 0x20b;
    info.sizeOfHeaders = rd32(opt + 60);
    info.imageBase = info.is64 ? rd64(opt + 24) : rd32(opt + 28);

    const std::uint8_t* sec = opt + optSize;
    for (std::uint16_t i = 0; i < numSections; ++i) {
        const std::uint8_t* s = sec + static_cast<std::size_t>(i) * 40;
        if (s + 40 > img.data() + img.size()) {
            break;
        }
        PeSection ps;
        char nm[9] = {0};
        std::memcpy(nm, s, 8);
        ps.name = nm;
        ps.virtualSize = rd32(s + 8);
        ps.virtualAddress = rd32(s + 12);
        ps.rawSize = rd32(s + 16);
        ps.rawOffset = rd32(s + 20);
        info.sections.push_back(std::move(ps));
    }
    return info;
}

} // namespace detail

// Reads an on-disk PE, scans its raw bytes for the pattern, and reports each
// match by file offset and, where the offset falls in a section or the headers,
// its RVA.
[[nodiscard]] inline PeScanResult scanPeFile(const std::string& path, const Pattern& pattern, bool firstOnly = false) {
    PeScanResult result;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        result.error = "could not open " + path;
        return result;
    }
    std::vector<std::uint8_t> img((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (img.empty()) {
        result.error = path + " is empty";
        return result;
    }
    auto info = detail::parsePeHeaders(img, result.error);
    if (!info) {
        return result;
    }
    result.info = std::move(*info);

    std::span<const std::uint8_t> sp(img.data(), img.size());
    const auto offsets = findAll(sp, pattern, firstOnly ? 1 : 0);
    for (std::size_t off : offsets) {
        PeMatch m;
        m.fileOffset = off;
        m.rva = result.info.offsetToRva(off);
        result.matches.push_back(m);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Resolve helpers
//
// These mirror Signature Lab's resolve line. `at` points at the first byte of
// the matched pattern; `matchVa` is that byte's runtime (or virtual) address;
// `fieldOffset` is where the field starts inside the pattern; `instrLen` is the
// length of the referring instruction.
// ---------------------------------------------------------------------------

// The kind of reference a signature encodes, matching Signature Lab.
enum class ReferenceKind : std::uint8_t {
    None,        // the match is the address
    Relative,    // call/jmp/jcc rel32:  target = matchVa + instrLen + rel32
    RipRelative, // [rip+disp32]:         target = matchVa + instrLen + disp32
    Absolute32,  // [disp32] / imm32:     target = *(uint32*)(at + fieldOffset)
    Absolute64,  // mov r64, imm64:       target = *(uint64*)(at + fieldOffset)
};

// Reads the signed 32-bit field at at + fieldOffset.
[[nodiscard]] inline std::int32_t readDisp32(const std::uint8_t* at, std::size_t fieldOffset) {
    std::int32_t v = 0;
    std::memcpy(&v, at + fieldOffset, 4);
    return v;
}

// The target of a call/jmp rel32 or a [rip+disp32] operand. Both use the same
// arithmetic: the field is relative to the end of the instruction.
[[nodiscard]] inline std::uint64_t resolveRipRelative(const std::uint8_t* at, std::size_t fieldOffset, std::uint64_t matchVa,
                                                      std::uint8_t instrLen) {
    const std::int64_t rel = readDisp32(at, fieldOffset);
    return matchVa + instrLen + static_cast<std::uint64_t>(rel);
}

// Alias: a near call or jump target uses the same rule.
[[nodiscard]] inline std::uint64_t resolveCallTarget(const std::uint8_t* at, std::size_t fieldOffset, std::uint64_t matchVa,
                                                     std::uint8_t instrLen) {
    return resolveRipRelative(at, fieldOffset, matchVa, instrLen);
}

// The general resolver, matching Signature Lab's Signature::resolution rule.
[[nodiscard]] inline std::uint64_t resolve(ReferenceKind kind, const std::uint8_t* at, std::size_t fieldOffset,
                                           std::uint64_t matchVa, std::uint8_t instrLen) {
    switch (kind) {
    case ReferenceKind::None:
        return matchVa;
    case ReferenceKind::Relative:
    case ReferenceKind::RipRelative:
        return resolveRipRelative(at, fieldOffset, matchVa, instrLen);
    case ReferenceKind::Absolute32: {
        std::uint32_t v = 0;
        std::memcpy(&v, at + fieldOffset, 4);
        return v;
    }
    case ReferenceKind::Absolute64: {
        std::uint64_t v = 0;
        std::memcpy(&v, at + fieldOffset, 8);
        return v;
    }
    }
    return matchVa;
}

// Follows a [rip+disp32] operand and reads the pointer-sized value it points
// at, through a reader. Returns nothing if that address cannot be read.
[[nodiscard]] inline std::optional<std::uint64_t> readRipRelative(const MemoryReader& reader, const std::uint8_t* at,
                                                                  std::size_t fieldOffset, std::uint64_t matchVa,
                                                                  std::uint8_t instrLen, std::size_t pointerSize) {
    const std::uint64_t target = resolveRipRelative(at, fieldOffset, matchVa, instrLen);
    std::uint64_t value = 0;
    if (!reader.read(target, &value, pointerSize)) {
        return std::nullopt;
    }
    return value;
}

// ---------------------------------------------------------------------------
// Live process module scanning (Windows only)
// ---------------------------------------------------------------------------

#ifdef _WIN32

struct ModuleLocation {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name;
    std::string path;
};

struct ProcessMatch {
    std::uint64_t address = 0; // virtual address in the target
    std::uint32_t rva = 0;     // address - module base
};

struct ProcessScanResult {
    ModuleLocation module;
    std::vector<ProcessMatch> matches;
    std::string error;

    [[nodiscard]] bool ok() const { return error.empty(); }
};

// Declarations. The implementation lives in the SIGSCAN_IMPLEMENTATION block so
// windows.h is included in exactly one translation unit.
[[nodiscard]] std::optional<ModuleLocation> findModule(std::uint32_t pid, std::string_view moduleName, std::string& error);
[[nodiscard]] ProcessScanResult scanProcessModule(std::uint32_t pid, std::string_view moduleName, const Pattern& pattern,
                                                  bool firstOnly = false);

#endif // _WIN32

} // namespace sigscan

// ---------------------------------------------------------------------------
// Windows implementation
//
// Define SIGSCAN_IMPLEMENTATION in exactly one .cpp before including this
// header to compile the live-process code. It is separated so windows.h is not
// pulled into every translation unit that only parses or scans a span.
// ---------------------------------------------------------------------------

#if defined(_WIN32) && defined(SIGSCAN_IMPLEMENTATION)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

namespace sigscan {

namespace detail {

// A reader over another process, using ReadProcessMemory.
class ProcessReader final : public MemoryReader {
public:
    explicit ProcessReader(HANDLE process) : process_(process) {}

    bool read(std::uint64_t address, void* destination, std::size_t size) const override {
        SIZE_T got = 0;
        if (!ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), destination, size, &got)) {
            return false;
        }
        return got == size;
    }

private:
    HANDLE process_;
};

inline std::string narrow(const wchar_t* w) {
    if (!w) {
        return {};
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
    return out;
}

inline bool iequalsAscii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) {
            return false;
        }
    }
    return true;
}

} // namespace detail

std::optional<ModuleLocation> findModule(std::uint32_t pid, std::string_view moduleName, std::string& error) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        error = "could not enumerate modules for pid " + std::to_string(pid) + " (need matching bitness and access)";
        return std::nullopt;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    std::optional<ModuleLocation> found;
    if (Module32FirstW(snap, &me)) {
        do {
            const std::string name = detail::narrow(me.szModule);
            if (moduleName.empty() || detail::iequalsAscii(name, moduleName)) {
                ModuleLocation loc;
                loc.base = reinterpret_cast<std::uintptr_t>(me.modBaseAddr);
                loc.size = me.modBaseSize;
                loc.name = name;
                loc.path = detail::narrow(me.szExePath);
                found = loc;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    if (!found) {
        error = "module '" + std::string(moduleName) + "' not found in pid " + std::to_string(pid);
    }
    return found;
}

ProcessScanResult scanProcessModule(std::uint32_t pid, std::string_view moduleName, const Pattern& pattern, bool firstOnly) {
    ProcessScanResult result;
    if (pattern.empty()) {
        result.error = "the pattern is empty";
        return result;
    }
    auto loc = findModule(pid, moduleName, result.error);
    if (!loc) {
        return result;
    }
    result.module = *loc;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        result.error = "OpenProcess failed for pid " + std::to_string(pid) + " (try running as the same user or elevated)";
        return result;
    }
    detail::ProcessReader reader(process);
    const auto hits = scanReader(reader, loc->base, loc->size, pattern, firstOnly);
    CloseHandle(process);

    for (std::uint64_t va : hits) {
        ProcessMatch m;
        m.address = va;
        m.rva = static_cast<std::uint32_t>(va - loc->base);
        result.matches.push_back(m);
    }
    return result;
}

} // namespace sigscan

#endif // _WIN32 && SIGSCAN_IMPLEMENTATION

#endif // SIGSCAN_HPP
