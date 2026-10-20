// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/metrics.h>

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>

namespace netsim {

namespace {
/** Read one "VmXXX:   N kB" field out of /proc/self/status. */
std::optional<uint64_t> ReadProcStatusKiB(const std::string& field)
{
    std::ifstream status{"/proc/self/status"};
    if (!status.is_open()) return std::nullopt;

    const std::string prefix{field + ":"};
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, prefix.size(), prefix) != 0) continue;
        try {
            return static_cast<uint64_t>(std::stoull(line.substr(prefix.size())));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}
} // namespace

std::optional<uint64_t> ResidentSetBytes()
{
    const auto kib{ReadProcStatusKiB("VmRSS")};
    if (!kib) return std::nullopt;
    return *kib * 1024;
}

std::optional<uint64_t> PeakResidentSetBytes()
{
    const auto kib{ReadProcStatusKiB("VmHWM")};
    if (!kib) return std::nullopt;
    return *kib * 1024;
}

} // namespace netsim
