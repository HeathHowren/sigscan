#pragma once

#include "sigscan/sigscan.hpp"

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace sigscan::test {

// A stand-in for a live process module: one contiguous region in a byte vector,
// with optional unreadable ranges (an uncommitted or guarded page). Unfilled
// bytes are a fixed pseudo-random filler rather than zeros, because a real
// module is not mostly zeros and a pattern of zeros would match everywhere.
//
// It implements sigscan::MemoryReader, so scanReader drives it exactly as it
// drives a real process, and the same page-boundary and partial-read paths run.
class FakeMemory final : public MemoryReader {
public:
    FakeMemory(std::uint64_t base, std::size_t size, std::uint64_t pageSize = 0x1000)
        : base_(base), page_(pageSize), bytes_(size) {
        std::uint32_t state = 0x12345678u;
        for (auto& b : bytes_) {
            state = state * 1664525u + 1013904223u;
            b = static_cast<std::uint8_t>(state >> 24);
        }
    }

    void write(std::uint64_t address, std::initializer_list<std::uint8_t> data) {
        std::size_t offset = static_cast<std::size_t>(address - base_);
        for (std::uint8_t b : data) {
            bytes_.at(offset++) = b;
        }
    }

    void writeBytes(std::uint64_t address, const std::uint8_t* data, std::size_t n) {
        std::memcpy(&bytes_.at(static_cast<std::size_t>(address - base_)), data, n);
    }

    void write32(std::uint64_t address, std::uint32_t value) {
        std::memcpy(&bytes_.at(static_cast<std::size_t>(address - base_)), &value, 4);
    }

    void write64(std::uint64_t address, std::uint64_t value) {
        std::memcpy(&bytes_.at(static_cast<std::size_t>(address - base_)), &value, 8);
    }

    void markUnreadable(std::uint64_t address, std::uint64_t size) { unreadable_.emplace_back(address, address + size); }

    std::uint64_t pageSize() const override { return page_; }

    bool read(std::uint64_t address, void* destination, std::size_t size) const override {
        for (std::size_t i = 0; i < size; ++i) {
            if (!readable(address + i)) {
                return false;
            }
        }
        std::memcpy(destination, bytes_.data() + (address - base_), size);
        return true;
    }

    std::uint64_t base() const { return base_; }
    std::uint64_t size() const { return bytes_.size(); }
    const std::vector<std::uint8_t>& bytes() const { return bytes_; }

private:
    bool readable(std::uint64_t address) const {
        if (address < base_ || address - base_ >= bytes_.size()) {
            return false;
        }
        for (const auto& [start, end] : unreadable_) {
            if (address >= start && address < end) {
                return false;
            }
        }
        return true;
    }

    std::uint64_t base_;
    std::uint64_t page_;
    std::vector<std::uint8_t> bytes_;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> unreadable_;
};

// The 32-bit displacement that a rel32 field must hold for a branch of
// `instructionLength` at `from` to reach `to`. Same helper as Signature Lab's.
inline std::uint32_t rel32(std::uint64_t from, std::uint8_t instructionLength, std::uint64_t to) {
    return static_cast<std::uint32_t>(to - (from + instructionLength));
}

} // namespace sigscan::test
