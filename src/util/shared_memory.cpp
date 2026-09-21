// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/shared_memory.h>

#include <random.h>
#include <tinyformat.h>
#include <util/syserror.h>

#include <cerrno>
#include <cstdint>
#include <utility>

#ifndef WIN32
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace util {

SharedMemory& SharedMemory::operator=(SharedMemory&& other) noexcept
{
    if (this != &other) {
        Reset();
        m_name = std::move(other.m_name);
        m_addr = std::exchange(other.m_addr, nullptr);
        m_size = std::exchange(other.m_size, 0);
        m_owner = std::exchange(other.m_owner, false);
    }
    return *this;
}

void SharedMemory::Reset()
{
#ifndef WIN32
    if (m_addr) munmap(m_addr, m_size);
    if (m_owner && !m_name.empty()) shm_unlink(m_name.c_str());
#endif
    m_addr = nullptr;
    m_size = 0;
    m_owner = false;
    m_name.clear();
}

SharedMemory SharedMemory::Create(size_t size, std::string& error)
{
#ifdef WIN32
    (void)size;
    error = "POSIX shared memory is not available on this platform";
    return {};
#else
    if (size == 0) {
        error = "shared memory size must not be zero";
        return {};
    }
    // Short name: macOS limits shared memory names to 31 characters.
    SharedMemory shm;
    int fd{-1};
    for (int attempt{0}; attempt < 8 && fd < 0; ++attempt) {
        shm.m_name = strprintf("/btc-trace-%i-%08x", getpid(), FastRandomContext().rand32());
        fd = shm_open(shm.m_name.c_str(), O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0 && errno != EEXIST) break;
    }
    if (fd < 0) {
        error = strprintf("shm_open('%s'): %s", shm.m_name, SysErrorString(errno));
        shm.m_name.clear();
        return {};
    }
    shm.m_owner = true;
    if (ftruncate(fd, static_cast<off_t>(size)) != 0) {
        error = strprintf("ftruncate('%s', %d): %s", shm.m_name, size, SysErrorString(errno));
        close(fd);
        shm_unlink(shm.m_name.c_str());
        shm.m_name.clear();
        shm.m_owner = false;
        return {};
    }
    void* addr{mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)};
    close(fd);
    if (addr == MAP_FAILED) {
        error = strprintf("mmap('%s', %d): %s", shm.m_name, size, SysErrorString(errno));
        shm_unlink(shm.m_name.c_str());
        shm.m_name.clear();
        shm.m_owner = false;
        return {};
    }
    shm.m_addr = addr;
    shm.m_size = size;
    return shm;
#endif
}

SharedMemory SharedMemory::Open(const std::string& name, size_t size, std::string& error)
{
#ifdef WIN32
    (void)name;
    (void)size;
    error = "POSIX shared memory is not available on this platform";
    return {};
#else
    if (size == 0) {
        error = "shared memory size must not be zero";
        return {};
    }
    const int fd{shm_open(name.c_str(), O_RDONLY, 0)};
    if (fd < 0) {
        error = strprintf("shm_open('%s'): %s", name, SysErrorString(errno));
        return {};
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || static_cast<uintmax_t>(st.st_size) < size) {
        error = strprintf("shared memory object '%s' is smaller than the expected %d bytes", name, size);
        close(fd);
        return {};
    }
    void* addr{mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0)};
    close(fd);
    if (addr == MAP_FAILED) {
        error = strprintf("mmap('%s', %d): %s", name, size, SysErrorString(errno));
        return {};
    }
    SharedMemory shm;
    shm.m_addr = addr;
    shm.m_size = size;
    return shm;
#endif
}

} // namespace util
