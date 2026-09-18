// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SHARED_MEMORY_H
#define BITCOIN_UTIL_SHARED_MEMORY_H

#include <cstddef>
#include <string>
#include <utility>

namespace util {

/**
 * A POSIX shared memory object (shm_open(3)) mapped into this process.
 *
 * Used to hand bulk data to a cooperating process on the same machine without
 * copying it through a socket. The creating process maps it read-write and
 * owns the name (it is unlinked when the object is destroyed); other processes
 * open it by name and map it read-only.
 *
 * Not available on Windows, where Create() and Open() always fail.
 */
class SharedMemory
{
public:
    SharedMemory() = default;
    ~SharedMemory() { Reset(); }
    SharedMemory(SharedMemory&& other) noexcept { *this = std::move(other); }
    SharedMemory& operator=(SharedMemory&& other) noexcept;
    SharedMemory(const SharedMemory&) = delete;
    SharedMemory& operator=(const SharedMemory&) = delete;

    //! Create a new shared memory object of `size` bytes under a unique name,
    //! mapped read-write, readable only by the current user. Returns an unset
    //! object and sets `error` on failure.
    static SharedMemory Create(size_t size, std::string& error);

    //! Open an existing shared memory object by name and map `size` bytes of
    //! it read-only. Returns an unset object and sets `error` on failure.
    static SharedMemory Open(const std::string& name, size_t size, std::string& error);

    explicit operator bool() const { return m_addr != nullptr; }
    const std::string& name() const { return m_name; }
    size_t size() const { return m_size; }
    //! Start of the mapping, or nullptr. Writable only if this process created it.
    std::byte* data() const { return static_cast<std::byte*>(m_addr); }

    //! Unmap and, if this process created the object, unlink its name.
    void Reset();

private:
    std::string m_name;
    void* m_addr{nullptr};
    size_t m_size{0};
    bool m_owner{false};
};

} // namespace util

#endif // BITCOIN_UTIL_SHARED_MEMORY_H
