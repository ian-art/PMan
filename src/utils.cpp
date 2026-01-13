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

#include "utils.h"
#include "constants.h"
#include "logger.h"
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <tlhelp32.h>
#include <mutex>
#include <shellapi.h>
#include <winhttp.h>
#include <unordered_set> // Required for IsSystemCriticalProcess
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Version.lib") // Required for GetFileVersionInfo

std::string WideToUtf8(const wchar_t* wstr)
{
	if (!wstr || !*wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    
    std::string result;
    try {
        result.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    } catch (const std::exception&) {
        return "[ERROR: String conversion failed]";
    }
    
    return result;
}

std::wstring ExeFromPath(const wchar_t* path)
{
    if (!path || !*path) return L"";
    const wchar_t* name = wcsrchr(path, L'\\');
    if (!name) name = path; else ++name;
    std::wstring s = name;
    asciiLower(s);
    return s;
}

bool IsSystemCriticalProcess(const std::wstring& exeName) {
    // Centralized Safety List (Defender + OS Core)
    // Ensures these processes are NEVER throttled, trimmed, or touched.
    static const std::unordered_set<std::wstring> SYS_PROCS = {
        // Windows Defender / Security
        L"msmpeng.exe", L"nissrv.exe", L"securityhealthservice.exe",
        L"sensecncproxy.exe", L"mpcmdrun.exe", L"smartscreen.exe",
        L"sgrmbroker.exe", L"sihost.exe",
        
        // System Core
        L"csrss.exe", L"lsass.exe", L"wininit.exe", L"services.exe",
        L"smss.exe", L"winlogon.exe", L"dwm.exe", L"spoolsv.exe",
        L"ntoskrnl.exe", L"system", L"fontdrvhost.exe", 
        L"taskhostw.exe", L"runtimebroker.exe"
    };
    return SYS_PROCS.count(exeName);
}

// asciiLower is now templated in header
void* GetNtProc(const char* procName)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    return hNtdll ? reinterpret_cast<void*>(GetProcAddress(hNtdll, procName)) : nullptr;
}

bool GetProcessIdentity(DWORD pid, ProcessIdentity& identity)
{
    if (pid == 0) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    
    FILETIME creationTime, exitTime, kernelTime, userTime;
    BOOL success = GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime);
    CloseHandle(h);
    
    if (success) {
        identity.pid = pid;
        identity.creationTime = creationTime;
        return true;
    }
    return false;
}

bool IsProcessIdentityValid(const ProcessIdentity& identity)
{
    if (identity.pid == 0) return false;
    ProcessIdentity current;
    if (!GetProcessIdentity(identity.pid, current)) return false;
    return identity == current;
}

bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle)
{
    if (needle.empty() || haystack.empty()) return false;
    
    // Fix Avoid string copies by using iterator-based search
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) { 
            return std::tolower(static_cast<unsigned char>(ch1)) == 
                   std::tolower(static_cast<unsigned char>(ch2)); 
        }
    );
    
    return it != haystack.end();
}

bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needle)
{
    if (needle.empty() || haystack.empty()) return false;
    
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](wchar_t ch1, wchar_t ch2) { 
            return std::towlower(ch1) == std::towlower(ch2); 
        }
    );
    
    return it != haystack.end();
}

std::string GetModeDescription(DWORD val)
{
    if (val == VAL_GAME) return "GAME MODE (0x28) - Optimized for consistent frame times";
    else if (val == VAL_BROWSER) return "BROWSER MODE (0x26) - Optimized for multitasking responsiveness";
    else if (val == 0xFFFFFFFF) return "ERROR - Unable to read registry";
    else return "CUSTOM/UNKNOWN (0x" + std::to_string(val) + ")";
}

DWORD GetCurrentPrioritySeparation()
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                            0, KEY_QUERY_VALUE, &key);
    if (rc != ERROR_SUCCESS) return 0xFFFFFFFF;
    
    DWORD val = 0;
    DWORD size = sizeof(val);
    rc = RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);
    RegCloseKey(key);
    
return (rc == ERROR_SUCCESS) ? val : 0xFFFFFFFF;
}

// Cache anti-cheat PIDs for 60 seconds to reduce syscall overhead
static std::unordered_map<DWORD, uint64_t> g_antiCheatCache;
static std::mutex g_antiCheatCacheMtx;

bool IsAntiCheatProtected(DWORD pid)
{
    {
        std::lock_guard lock(g_antiCheatCacheMtx);
        uint64_t now = GetTickCount64();
        auto it = g_antiCheatCache.find(pid);
        if (it != g_antiCheatCache.end()) {
            if (now - it->second < 60000) return true; // Still cached
            g_antiCheatCache.erase(it);
        }
    }

    // 1. Check Process Name first (Cheap)
    ProcessIdentity identity;
    if (GetProcessIdentity(pid, identity)) {
        UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProc) {
            wchar_t path[MAX_PATH];
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
            if (IsAntiCheatProcess(ExeFromPath(path))) {
                std::lock_guard lock(g_antiCheatCacheMtx);
                g_antiCheatCache[pid] = GetTickCount64();
                return true;
            }
        }
        }
    }
    
    // Legacy expensive check removed for performance. 
    // Enable only if deep inspection of injected AC modules is strictly required.
    return false;
}

DWORD GetParentProcessId(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                DWORD parent = pe.th32ParentProcessID;
                CloseHandle(hSnap);
                return parent;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}

DWORD GetDwmProcessId()
{
    // Method 1: Registry (Fastest)
    HKEY hKey;
    DWORD dwmPid = 0;
    DWORD size = sizeof(dwmPid);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
                      L"Software\\Microsoft\\Windows\\DWM", 
                      0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProcessId", NULL, NULL, 
                        reinterpret_cast<LPBYTE>(&dwmPid), &size) == ERROR_SUCCESS) {
            // Verify PID actually exists and is DWM (PID reuse protection)
            ProcessIdentity id;
            if (GetProcessIdentity(dwmPid, id)) {
                // Double check name
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwmPid);
                if (hProc) {
                    wchar_t path[MAX_PATH];
                    DWORD sz = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
                        if (ExeFromPath(path) == L"dwm.exe") {
                            RegCloseKey(hKey);
                            CloseHandle(hProc);
                            return dwmPid;
                        }
                    }
                    CloseHandle(hProc);
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    // Method 2: Snapshot Fallback
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap.get(), &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"dwm.exe") == 0) {
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap.get(), &pe));
    }
    
    return 0;
}

DWORD GetProcessIdByName(const std::wstring& exeName)
{
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap.get(), &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap.get(), &pe));
    }
    return 0;
}

// FIX: Removed static to allow usage in performance.cpp
ULONGLONG FileTimeToULL(const FILETIME& ft) {
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// FIX: Centralized Anti-Cheat detection
bool IsAntiCheatProcess(const std::wstring& exeName)
{
    if (exeName == L"riot-vanguard.exe" || 
        exeName == L"easyanticheat.exe" || 
        exeName == L"beservice.exe" || 
        exeName == L"navapsvc.exe")
    {
        return true;
    }
    return false;
}

double GetCpuLoad() {
    // Fix: Protect static state with mutex
    static std::mutex mtx;
    std::lock_guard lock(mtx);

    static FILETIME prevIdle = {0}, prevKernel = {0}, prevUser = {0};
    FILETIME idle, kernel, user;

    if (!GetSystemTimes(&idle, &kernel, &user)) return 0.0;

    ULONGLONG idleDiff = FileTimeToULL(idle) - FileTimeToULL(prevIdle);
    ULONGLONG kernelDiff = FileTimeToULL(kernel) - FileTimeToULL(prevKernel);
    ULONGLONG userDiff = FileTimeToULL(user) - FileTimeToULL(prevUser);

    prevIdle = idle;
    prevKernel = kernel;
    prevUser = user;

    ULONGLONG total = kernelDiff + userDiff;
	if (total == 0) return 0.0;

    return 100.0 * (1.0 - (double)idleDiff / (double)total);
}

HANDLE OpenProcessSafe(DWORD access, DWORD pid, const char* logTag)
{
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (!h && logTag)
    {
        Log(std::string(logTag) + " Failed to open process " + std::to_string(pid) + 
            ": " + std::to_string(GetLastError()));
    }
    return h;
}

void ForEachProcess(std::function<void(const PROCESSENTRY32W&)> callback)
{
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap.get(), &pe)) {
        do {
            callback(pe);
        } while (Process32NextW(hSnap.get(), &pe));
    }
}

bool RegReadDword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD& outVal)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return false;
    UniqueRegKey keyGuard(key);

    DWORD size = sizeof(DWORD);
	return RegQueryValueExW(key, value, nullptr, nullptr, reinterpret_cast<BYTE*>(&outVal), &size) == ERROR_SUCCESS;
}

// ------------------- UPDATER IMPLEMENTATION -------------------
static bool HttpRequest(const wchar_t* path, std::string& outData, bool binary)
{
    bool result = false;

    HINTERNET hSession = WinHttpOpen(
        L"PriorityManager/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
        return false;

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        UPDATE_HOST,
        INTERNET_DEFAULT_HTTPS_PORT,
        0);

    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(
        hRequest,
        WINHTTP_OPTION_REDIRECT_POLICY,
        &redirectPolicy,
        sizeof(redirectPolicy));

    if (WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0) &&
        WinHttpReceiveResponse(hRequest, nullptr))
    {
        std::vector<char> buffer;
        DWORD size = 0;

        while (WinHttpQueryDataAvailable(hRequest, &size) && size > 0) {
            std::vector<char> chunk(size);
            DWORD read = 0;

            if (!WinHttpReadData(hRequest, chunk.data(), size, &read))
                break;

            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + read);
        }

        if (!buffer.empty()) {
            if (!binary) {
                // Strip UTF-8 BOM if present
                if (buffer.size() >= 3 &&
                    static_cast<unsigned char>(buffer[0]) == 0xEF &&
                    static_cast<unsigned char>(buffer[1]) == 0xBB &&
                    static_cast<unsigned char>(buffer[2]) == 0xBF)
                {
                    buffer.erase(buffer.begin(), buffer.begin() + 3);
                }
            }

            outData.assign(buffer.begin(), buffer.end());
            result = true;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

return result;
}

std::wstring GetCurrentExeVersion()
{
    wchar_t path[MAX_PATH]{};
    // If the function fails, the return value is 0, path remains empty.
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0)
        return L"0.0.0.0";

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &handle);
    if (size == 0)
        return L"0.0.0.0";

	std::vector<BYTE> buffer(size);
    // Fix C6388: Pass 0 as handle, as required/ignored by spec
    if (!GetFileVersionInfoW(path, 0, size, buffer.data()))
        return L"0.0.0.0";

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;

    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<void**>(&ffi), &len))
        return L"0.0.0.0";

	if (len == 0 || ffi->dwSignature != VS_FFI_SIGNATURE)
        return L"0.0.0.0";

    // Use C++ string construction to avoid buffer heuristics
	return std::to_wstring(HIWORD(ffi->dwFileVersionMS)) + L"." +
           std::to_wstring(LOWORD(ffi->dwFileVersionMS)) + L"." +
           std::to_wstring(HIWORD(ffi->dwFileVersionLS)) + L"." +
           std::to_wstring(LOWORD(ffi->dwFileVersionLS));
}

bool VerifyUpdateConnection()
{
    HINTERNET hSession = WinHttpOpen(
        L"PriorityManager/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) return false;

    bool connected = false;
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        UPDATE_HOST,
        INTERNET_DEFAULT_HTTPS_PORT,
        0);

    if (hConnect)
    {
        // Fix: WinHttpConnect is lazy. Use HEAD request to verify actual connectivity.
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"HEAD", 
            UPDATE_VER_PATH, 
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (hRequest)
        {
            // Ensure redirects are followed for robustness
            DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hRequest, nullptr))
            {
                DWORD statusCode = 0;
                DWORD size = sizeof(statusCode);
                
                // If we get ANY status code, we have reached the server
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX))
                {
                    connected = true;
                }
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }

    WinHttpCloseHandle(hSession);
    return connected;
}

bool CheckForUpdates(std::wstring& outLatestVer)
{
    std::string data;
    if (HttpRequest(UPDATE_VER_PATH, data, false)) {
        // Safe Trim: Avoid npos/out_of_range errors on empty strings
        size_t first = data.find_first_not_of(" \n\r\t");
        if (first == std::string::npos) return false; // String is all whitespace or empty

        size_t last = data.find_last_not_of(" \n\r\t");
        std::string cleanData = data.substr(first, (last - first + 1));
        
        if (!cleanData.empty()) {
            std::wstring latest = std::wstring(cleanData.begin(), cleanData.end());
            outLatestVer = latest;
            
            // Compare against dynamic resource version
            std::wstring current = GetCurrentExeVersion();
            return latest != current;
        }
    }
    return false;
}

bool DownloadUpdate(const std::wstring& savePath)
{
    std::string data;
    if (HttpRequest(UPDATE_BIN_PATH, data, true)) {
        HANDLE hFile = CreateFileW(savePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, data.data(), (DWORD)data.size(), &written, nullptr);
            CloseHandle(hFile);
            return written == data.size();
        }
    }
    return false;
}

void InstallUpdateAndRestart(const std::wstring& newExePath, bool isPaused)
{
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    // Determine launch arguments
    std::string args = "/silent";
    if (isPaused) args += " --paused";

    // Create a self-deleting batch script
    // 1. Timeout to let this process exit
    // 2. Move new file over old file
    // 3. Start new file
    // 4. Delete batch file
    std::wstring batPath = std::wstring(selfPath) + L".update.bat";
    
    std::string batScript = "@echo off\r\n"
                            "timeout /t 1 /nobreak >nul\r\n"
                            "move /y \"" + WideToUtf8(newExePath.c_str()) + "\" \"" + WideToUtf8(selfPath) + "\" >nul\r\n"
                            "start \"\" \"" + WideToUtf8(selfPath) + "\" " + args + "\r\n"
                            "del \"%~f0\"";

    HANDLE hFile = CreateFileW(batPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, batScript.c_str(), (DWORD)batScript.length(), &written, nullptr);
        CloseHandle(hFile);

        // Execute the batch script hidden
        ShellExecuteW(nullptr, L"open", batPath.c_str(), nullptr, nullptr, SW_HIDE);
        
        // Exit immediately to release file lock
        ExitProcess(0);
    }
}
