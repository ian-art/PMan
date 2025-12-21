#ifndef PMAN_UTILS_H
#define PMAN_UTILS_H

#include "types.h"
#include <string>
#include <memory>

// Convert wide string to UTF-8
std::string WideToUtf8(const wchar_t* wstr);

// Extract executable name from a full path
std::string ExeFromPath(const wchar_t* path);

// Convert ASCII string to lowercase in-place
void asciiLower(std::string& s);

// Get process identity (PID + creation time)
bool GetProcessIdentity(DWORD pid, ProcessIdentity& identity);

// Check if a process identity is still valid
bool IsProcessIdentityValid(const ProcessIdentity& identity);

// Case-insensitive containment check
bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle);

// RAII Wrapper for Windows HANDLEs
struct HandleDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

// RAII Wrapper for Registry HKEYs
struct RegKeyDeleter {
    void operator()(HKEY h) const {
        if (h) RegCloseKey(h);
    }
};
using UniqueRegKey = std::unique_ptr<std::remove_pointer<HKEY>::type, RegKeyDeleter>;

#endif // PMAN_UTILS_H