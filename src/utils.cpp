#include "utils.h"

std::string WideToUtf8(const wchar_t* wstr)
{
    if (!wstr || !*wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::string ExeFromPath(const wchar_t* path)
{
    if (!path || !*path) return "";
    const wchar_t* name = wcsrchr(path, L'\\');
    if (!name) name = path; else ++name;
    std::string s = WideToUtf8(name);
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
    
    std::string haystackLower = haystack;
    std::string needleLower = needle;
    asciiLower(haystackLower);
    asciiLower(needleLower);
    
    return haystackLower.find(needleLower) != std::string::npos;
}