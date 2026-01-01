#include "utils.h"
#include "constants.h"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <tlhelp32.h>
#include <mutex> // Fix: Added for thread safety

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

bool IsAntiCheatProtected(DWORD pid)
{
    // 1. Check Process Name first (Cheap)
    ProcessIdentity identity;
    if (GetProcessIdentity(pid, identity)) {
        UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProc) {
            wchar_t path[MAX_PATH];
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
                if (IsAntiCheatProcess(ExeFromPath(path))) return true;
            }
        }
    }

    // 2. Check Loaded Modules (Expensive)
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me32 = {sizeof(me32)};
    if (Module32FirstW(hSnap.get(), &me32)) 
    {
        do {
            std::wstring mod = me32.szModule;
            if (mod.find(L"EasyAntiCheat") != std::wstring::npos ||
                mod.find(L"BEClient") != std::wstring::npos || 
                mod.find(L"vgk") != std::wstring::npos ||      
                mod.find(L"EAC") != std::wstring::npos) 
            {
                return true;
            }
        } while (Module32NextW(hSnap.get(), &me32));
    }
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