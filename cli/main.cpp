// sigscan.exe: parse a byte signature and find it in an on-disk PE or a live
// process module.
//
//   sigscan --file game.exe 48 8B 05 ?? ?? ?? ??
//   sigscan --pid 1234 --module game.exe "48 8B 05 ? ? ? ?"
//   sigscan --pid 1234 --module game.exe --first "\x48\x8B\x05" "xxx"
//
// SIGSCAN_IMPLEMENTATION is defined here, and only here, so the live-process
// code (which includes windows.h) is compiled in exactly one translation unit.

#define SIGSCAN_IMPLEMENTATION
#include "sigscan/sigscan.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

void printUsage() {
    std::puts("sigscan " SIGSCAN_CLI_VERSION " - find a byte signature in a PE file or a live process module.\n"
              "\n"
              "Usage:\n"
              "  sigscan --file <path> [options] <pattern>\n"
              "  sigscan --pid <n> --module <name> [options] <pattern>\n"
              "\n"
              "Target (pick one):\n"
              "  --file <path>        Scan an on-disk PE. Reports RVA and file offset.\n"
              "  --pid <n>            Scan a live process (Windows). Needs --module.\n"
              "  --module <name>      Module in the process, e.g. game.exe. Empty means the main module.\n"
              "\n"
              "Options:\n"
              "  --first              Stop at the first match (default: report all).\n"
              "  --limit <n>          Report at most n matches.\n"
              "  --help               This message.\n"
              "\n"
              "Pattern forms (all understood):\n"
              "  x64dbg      48 8B 05 ?? ?? ?? ??        (a whole wildcard byte is ??, a nibble is 4?)\n"
              "  IDA         48 8B 05 ? ? ? ?\n"
              "  code+mask   \"\\x48\\x8B\\x05\" \"xxx\"       (bytes then an x/? mask)\n"
              "  C++ array   { 0x48, 0x8B, 0x05 } \"xxx\"\n"
              "  Pointer Lab aobscanmodule(INJECT, game.exe, 48 8B 05 ?? ?? ?? ??)\n"
              "\n"
              "The pattern is every non-option argument, joined with spaces, so it can be\n"
              "quoted or left bare.");
}

std::string joinPattern(const std::vector<std::string>& parts) {
    std::string out;
    for (const std::string& s : parts) {
        if (!out.empty()) {
            out += ' ';
        }
        out += s;
    }
    return out;
}

int scanFile(const std::string& path, const sigscan::Pattern& pattern, bool firstOnly, std::size_t limit) {
    sigscan::PeScanResult r = sigscan::scanPeFile(path, pattern, firstOnly);
    if (!r.ok()) {
        std::fprintf(stderr, "error: %s\n", r.error.c_str());
        return 2;
    }
    std::printf("file    %s (%s, %zu sections)\n", path.c_str(), r.info.is64 ? "PE32+" : "PE32", r.info.sections.size());
    std::printf("backend %s\n", sigscan::backendName(sigscan::activeBackend()));

    std::size_t shown = 0;
    for (const sigscan::PeMatch& m : r.matches) {
        if (limit != 0 && shown >= limit) {
            break;
        }
        // Name the section the offset falls in, for context.
        const char* section = "headers/slack";
        for (const sigscan::PeSection& s : r.info.sections) {
            if (s.rawSize != 0 && m.fileOffset >= s.rawOffset &&
                m.fileOffset < static_cast<std::uint64_t>(s.rawOffset) + s.rawSize) {
                section = s.name.c_str();
                break;
            }
        }
        if (m.rva) {
            std::printf("match   RVA 0x%08X  file offset 0x%08llX  %s\n", *m.rva,
                        static_cast<unsigned long long>(m.fileOffset), section);
        } else {
            std::printf("match   RVA -           file offset 0x%08llX  %s\n",
                        static_cast<unsigned long long>(m.fileOffset), section);
        }
        ++shown;
    }
    std::printf("%zu match%s\n", r.matches.size(), r.matches.size() == 1 ? "" : "es");
    return r.matches.empty() ? 1 : 0;
}

#ifdef _WIN32
int scanProcess(std::uint32_t pid, const std::string& moduleName, const sigscan::Pattern& pattern, bool firstOnly,
                std::size_t limit) {
    sigscan::ProcessScanResult r = sigscan::scanProcessModule(pid, moduleName, pattern, firstOnly);
    if (!r.ok()) {
        std::fprintf(stderr, "error: %s\n", r.error.c_str());
        return 2;
    }
    std::printf("module  %s  base 0x%llX  size 0x%llX\n", r.module.name.c_str(),
                static_cast<unsigned long long>(r.module.base), static_cast<unsigned long long>(r.module.size));
    std::printf("backend %s\n", sigscan::backendName(sigscan::activeBackend()));
    std::size_t shown = 0;
    for (const sigscan::ProcessMatch& m : r.matches) {
        if (limit != 0 && shown >= limit) {
            break;
        }
        std::printf("match   VA 0x%llX  RVA 0x%08X\n", static_cast<unsigned long long>(m.address), m.rva);
        ++shown;
    }
    std::printf("%zu match%s\n", r.matches.size(), r.matches.size() == 1 ? "" : "es");
    return r.matches.empty() ? 1 : 0;
}
#endif

} // namespace

int main(int argc, char** argv) {
    std::string file;
    std::string moduleName;
    bool haveModule = false;
    long pid = -1;
    bool firstOnly = false;
    std::size_t limit = 0;
    std::vector<std::string> patternParts;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: %s needs a value\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") {
            printUsage();
            return 0;
        } else if (a == "--file") {
            file = next("--file");
        } else if (a == "--pid") {
            pid = std::strtol(next("--pid"), nullptr, 0);
        } else if (a == "--module") {
            moduleName = next("--module");
            haveModule = true;
        } else if (a == "--first") {
            firstOnly = true;
        } else if (a == "--limit") {
            limit = static_cast<std::size_t>(std::strtoul(next("--limit"), nullptr, 0));
        } else {
            patternParts.push_back(a);
        }
    }

    if (patternParts.empty()) {
        printUsage();
        return 2;
    }

    const std::string patternText = joinPattern(patternParts);
    sigscan::ParseResult parsed = sigscan::parse(patternText);
    if (!parsed) {
        std::fprintf(stderr, "error: %s\n", parsed.error.c_str());
        std::fprintf(stderr, "       pattern was: %s\n", patternText.c_str());
        return 2;
    }
    std::printf("pattern %s  (%zu bytes, %zu wildcards)\n", sigscan::format(parsed.pattern, sigscan::Format::X64dbg).c_str(),
                parsed.pattern.size(), parsed.pattern.wildcardCount());

    if (!file.empty()) {
        return scanFile(file, parsed.pattern, firstOnly, limit);
    }
    if (pid >= 0) {
        if (!haveModule) {
            std::fprintf(stderr, "error: --pid needs --module\n");
            return 2;
        }
#ifdef _WIN32
        return scanProcess(static_cast<std::uint32_t>(pid), moduleName, parsed.pattern, firstOnly, limit);
#else
        std::fprintf(stderr, "error: live-process scanning is Windows only\n");
        return 2;
#endif
    }
    std::fprintf(stderr, "error: pick a target: --file <path>, or --pid <n> --module <name>\n");
    return 2;
}
