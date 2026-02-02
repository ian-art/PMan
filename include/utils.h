/*
 * This file is part of Priority Manager (PMan).
 *
 * Copyright (c) 2025 Ian Anthony R. Tancinco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
std::wstring GetProcessNameFromPid(DWORD pid); // [FIX] Added missing helper
bool IsSystemCriticalProcess(const std::wstring& exeName); // Defender/System Exclusion
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

// Registry Anti-Hammering
bool RegWriteDwordCached(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD data);
bool RegWriteString(HKEY root, const wchar_t* subkey, const wchar_t* value, const std::wstring& data);
bool RegDeleteKeyRecursive(HKEY root, const wchar_t* subkey);

// Updater Functions
void OpenUpdatePage();

// RAII Wrapper for Windows HANDLEs (Moved to types.h)
// struct HandleDeleter ... using UniqueHandle ...

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

// Get DWM Process ID (Shared Utility)
DWORD GetDwmProcessId();

// Generic helper to find system processes (e.g., audiodg.exe)
DWORD GetProcessIdByName(const std::wstring& exeName);

// Disable Scheduled Task via COM
bool DisableScheduledTask(const std::wstring& taskPath);

// Responsiveness Check
bool IsWindowHung(HWND hwnd);

#endif // PMAN_UTILS_H
