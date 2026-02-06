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
#include "nt_wrapper.h"
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <tlhelp32.h>
#include <mutex>
#include <shellapi.h>
#include <unordered_set> // Required for IsSystemCriticalProcess
#include <taskschd.h>
#include <comdef.h>
#include <shlwapi.h> // Required for SHDeleteKeyW
#pragma comment(lib, "Version.lib") // Required for GetFileVersionInfo
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "Shlwapi.lib")

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

std::wstring Utf8ToWide(const char* str)
{
    if (!str || !*str) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (len <= 0) return L"";
    
    std::wstring result;
    try {
        result.resize(len - 1);
        MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], len);
    } catch (...) {
        return L"";
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

// [FIX] Helper Implementation for Circuit Breaker
std::wstring GetProcessNameFromPid(DWORD pid)
{
    if (pid == 0) return L"";
    if (pid == 4) return L"system"; 

    // PROCESS_QUERY_LIMITED_INFORMATION is sufficient for getting the name
    // and works on protected processes where PROCESS_QUERY_INFORMATION fails.
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return L"";

    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
        return ExeFromPath(path);
    }
    return L"";
}

bool IsSystemCriticalProcess(const std::wstring& exeName) {
    // Centralized Safety List (Defender + OS Core)
    // Ensures these processes are NEVER throttled, trimmed, or touched.
    static const std::unordered_set<std::wstring> SYS_PROCS = {
        // Windows Defender / Security
        L"msmpeng.exe", L"nissrv.exe", L"securityhealthservice.exe",
        L"sensecncproxy.exe", L"mpcmdrun.exe", L"smartscreen.exe",
        L"sgrmbroker.exe", L"sihost.exe",
        
		// ADD THESE FOR FULL WINDOWS 10/11 COMPATIBILITY:
        L"searchapp.exe",          // Win10 Search
        L"searchhost.exe",         // Win11 Search
        L"startmenuexperiencehost.exe", // Win11 Start Menu
        L"textinputhost.exe",      // Emoji panel / Touch keyboard
		
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
    return NtWrapper::GetProcAddress(procName);
}

bool GetProcessIdentity(DWORD pid, ProcessIdentity& identity)
{
    if (pid == 0) return false;
    UniqueHandle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) return false;
    
    FILETIME creationTime, exitTime, kernelTime, userTime;
    BOOL success = GetProcessTimes(h.get(), &creationTime, &exitTime, &kernelTime, &userTime);
    
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
    HKEY rawKey = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                            0, KEY_QUERY_VALUE, &rawKey);
    if (rc != ERROR_SUCCESS) return 0xFFFFFFFF;
    
    UniqueRegKey key(rawKey);
    DWORD val = 0;
    DWORD size = sizeof(val);
    rc = RegQueryValueExW(key.get(), L"Win32PrioritySeparation", nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);
    
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
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap.get(), &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                return pe.th32ParentProcessID;
            }
        } while (Process32NextW(hSnap.get(), &pe));
    }
    return 0;
}

DWORD GetDwmProcessId()
{
    // Method 1: Registry (Fastest)
    HKEY rawKey;
    DWORD dwmPid = 0;
    DWORD size = sizeof(dwmPid);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
                      L"Software\\Microsoft\\Windows\\DWM", 
                      0, KEY_QUERY_VALUE, &rawKey) == ERROR_SUCCESS) {
        UniqueRegKey hKey(rawKey);
        if (RegQueryValueExW(hKey.get(), L"ProcessId", NULL, NULL, 
                        reinterpret_cast<LPBYTE>(&dwmPid), &size) == ERROR_SUCCESS) {
            // Verify PID actually exists and is DWM (PID reuse protection)
            ProcessIdentity id;
            if (GetProcessIdentity(dwmPid, id)) {
                // Double check name
                UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwmPid));
                if (hProc) {
                    wchar_t path[MAX_PATH];
                    DWORD sz = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
                        if (ExeFromPath(path) == L"dwm.exe") {
                            return dwmPid;
                        }
                    }
                }
            }
        }
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

// FIX: Centralized Anti-Cheat detection (Architecture Aware)
bool IsAntiCheatProcess(const std::wstring& exeName)
{
    // Common Anti-Cheats (x86/x64)
    static const std::unordered_set<std::wstring> AC_COMMON = { 
        L"riot-vanguard.exe", L"easyanticheat.exe", L"beservice.exe", L"navapsvc.exe",
        L"vgk.exe", L"faceitclient.exe"
    };

    // ARM64 Specific Variants (Hypothetical/Future-proofing)
    static const std::unordered_set<std::wstring> AC_ARM64 = { 
        L"vanguard-arm64.exe", L"eas-arm64.exe", L"beservice_a64.exe"
    };

    if (AC_COMMON.count(exeName)) return true;

// [FIX] Always check ARM64 list to support x64 apps running on ARM64 (Prism emulation)
if (AC_ARM64.count(exeName)) return true;

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

// Registry Anti-Hammering Implementation
bool RegWriteDwordCached(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD data)
{
    HKEY rawKey = nullptr;
    // Open with both QUERY and SET access
    LONG rc = RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &rawKey);

    // If key doesn't exist, try to create it
    if (rc != ERROR_SUCCESS) {
        rc = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &rawKey, nullptr);
    }

    if (rc != ERROR_SUCCESS) return false;

    UniqueRegKey key(rawKey);
    DWORD currentVal = 0;
    DWORD size = sizeof(currentVal);

    // Check current value
    if (RegQueryValueExW(key.get(), value, nullptr, nullptr, reinterpret_cast<BYTE*>(&currentVal), &size) == ERROR_SUCCESS)
    {
        // If strictly equal, skip the write (Anti-Hammering)
        if (currentVal == data) return true;
    }

    // Value differs or doesn't exist; perform write
    return RegSetValueExW(key.get(), value, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&data), sizeof(data)) == ERROR_SUCCESS;
}

bool RegWriteString(HKEY root, const wchar_t* subkey, const wchar_t* value, const std::wstring& data)
{
    HKEY rawKey = nullptr;
    LONG rc = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &rawKey, nullptr);
    if (rc != ERROR_SUCCESS) return false;
    UniqueRegKey key(rawKey);

    return RegSetValueExW(key.get(), value, 0, REG_SZ, 
        reinterpret_cast<const BYTE*>(data.c_str()), 
        static_cast<DWORD>((data.length() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

bool RegDeleteKeyRecursive(HKEY root, const wchar_t* subkey)
{
    // SHDeleteKey is the standard way to delete keys with subkeys
    return SHDeleteKeyW(root, subkey) == ERROR_SUCCESS;
}

// ------------------- UPDATER IMPLEMENTATION -------------------

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

void OpenUpdatePage()
{
    ShellExecuteW(nullptr, L"open", GITHUB_RELEASES_URL, nullptr, nullptr, SW_SHOWNORMAL);
}

// Task Silencer Implementation
bool DisableScheduledTask(const std::wstring& taskPath)
{
    // Ensure COM is initialized for this thread
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    
    ITaskService* pService = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        if (SUCCEEDED(hrInit)) CoUninitialize();
        return false;
    }

    // Connect to local service
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        if (SUCCEEDED(hrInit)) CoUninitialize();
        return false;
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        if (SUCCEEDED(hrInit)) CoUninitialize();
        return false;
    }

    // Attempt to locate and disable the task
    IRegisteredTask* pTask = nullptr;
    hr = pRootFolder->GetTask(_bstr_t(taskPath.c_str()), &pTask);
    
    bool result = false;
    if (SUCCEEDED(hr)) {
        // Disable the task
        hr = pTask->put_Enabled(VARIANT_FALSE);
        if (SUCCEEDED(hr)) {
            result = true;
            Log("[TASK] Disabled telemetry task: " + WideToUtf8(taskPath.c_str()));
        } else {
            Log("[TASK] Failed to disable task: " + WideToUtf8(taskPath.c_str()) + " HR=" + std::to_string(hr));
        }
        pTask->Release();
    } else {
        // Task likely doesn't exist on this version of Windows
        // Silent fail or debug log
    }

    pRootFolder->Release();
    pService->Release();
    if (SUCCEEDED(hrInit)) CoUninitialize();
    
    return result;
}

bool IsWindowHung(HWND hwnd)
{
    if (!hwnd) return false;
    return IsHungAppWindow(hwnd) != 0;
}
