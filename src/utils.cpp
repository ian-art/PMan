#include "utils.h"
#include "constants.h"
#include <algorithm>
#include <cctype>
#include <cwctype>

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

void asciiLower(std::string& s)
{
    for (char& c : s) 
    {
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    }
}

void asciiLower(std::wstring& s)
{
    for (wchar_t& c : s) 
    {
        if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
    }
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