#ifndef PMAN_UTILS_H
#define PMAN_UTILS_H

#include "types.h"
#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <windows.h>
#include <tlhelp32.h>

// Helpers
std::string WideToUtf8(const wchar_t* wstr);
std::wstring ExeFromPath(const wchar_t* path);
ULONGLONG FileTimeToULL(const FILETIME& ft); // Shared utility
bool IsAntiCheatProcess(const std::wstring& exeName); // Centralized AC check

// Retrieve file version from the executable's VERSIONINFO resource
std::wstring GetCurrentExeVersion();

// Convert ASCII string to lowercase in-place (Templated)
template<typename T>
void asciiLower(T& s) {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    }
}

// Helper to get NTDLL function pointers
void* GetNtProc(const char* procName);

// Get process identity (PID + creation time)
bool GetProcessIdentity(DWORD pid, ProcessIdentity& identity);

// Check if a process identity is still valid
bool IsProcessIdentityValid(const ProcessIdentity& identity);

// Case-insensitive containment check
bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle);
bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needle);

// Get friendly description for registry mode value
std::string GetModeDescription(DWORD val);

DWORD GetCurrentPrioritySeparation();

// Get Global CPU Load Percentage
double GetCpuLoad();

// RAII Helpers
HANDLE OpenProcessSafe(DWORD access, DWORD pid, const char* logTag = nullptr);
void ForEachProcess(std::function<void(const PROCESSENTRY32W&)> callback);

// Registry Helpers
bool RegReadDword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD& outVal);

// Updater Functions
bool VerifyUpdateConnection(); // Replaces Winsock check with WinHTTP
bool CheckForUpdates(std::wstring& outLatestVer);
bool DownloadUpdate(const std::wstring& savePath);
void InstallUpdateAndRestart(const std::wstring& newExePath);

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

// Check for known anti-cheat modules in process
bool IsAntiCheatProtected(DWORD pid);

// Get Parent PID (Non-ETW fallback)
DWORD GetParentProcessId(DWORD pid);

#endif // PMAN_UTILS_H