// A throughput benchmark for the span scanner. It fills a large buffer with
// pseudo-random bytes, plants one match at the end so the whole buffer is
// scanned, and times findAll over several passes. Prints the active backend and
// the throughput, which is the number quoted in the README.

#include "sigscan/sigscan.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <span>
#include <vector>

int main(int argc, char** argv) {
    std::size_t bytes = 256u * 1024u * 1024u; // 256 MiB
    int passes = 5;
    if (argc > 1) {
        bytes = static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 0)) * 1024u * 1024u;
    }
    if (argc > 2) {
        passes = std::atoi(argv[2]);
    }

    std::vector<std::uint8_t> buf(bytes);
    std::uint32_t s = 0x1234567u;
    for (auto& b : buf) {
        s = s * 1664525u + 1013904223u;
        b = static_cast<std::uint8_t>(s >> 24);
    }

    // A 12-byte pattern with wildcards, unlikely to occur by chance, planted once.
    const auto p = sigscan::parse("48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ??");
    if (!p) {
        std::fprintf(stderr, "bad pattern\n");
        return 1;
    }
    const std::uint8_t planted[] = {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x89, 0x05, 0, 0};
    std::copy(std::begin(planted), std::end(planted), buf.end() - static_cast<std::ptrdiff_t>(sizeof planted));

    std::span<const std::uint8_t> sp(buf.data(), buf.size());
    std::size_t matches = 0;
    double best = 1e300;
    for (int i = 0; i < passes; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        const auto hits = sigscan::findAll(sp, *p);
        const auto t1 = std::chrono::steady_clock::now();
        matches = hits.size();
        const double secs = std::chrono::duration<double>(t1 - t0).count();
        if (secs < best) {
            best = secs;
        }
    }
    const double gbps = (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) / best;
    std::printf("backend    %s\n", sigscan::backendName(sigscan::activeBackend()));
    std::printf("buffer     %zu MiB\n", bytes / (1024u * 1024u));
    std::printf("matches    %zu\n", matches);
    std::printf("best pass  %.3f ms\n", best * 1000.0);
    std::printf("throughput %.2f GB/s\n", gbps);
    return 0;
}
