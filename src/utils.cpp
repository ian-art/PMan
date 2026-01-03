#include "utils.h"
#include "constants.h"
#include "logger.h"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <tlhelp32.h>
#include <mutex>
#include <shellapi.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

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
    // This relies on the consolidated list in IsAntiCheatProcess. 
    // Fallback to module snapshot is disabled by default to prevent system-wide lag.
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

bool CheckForUpdates(std::wstring& outLatestVer)
{
    std::string data;
    if (HttpRequest(UPDATE_VER_PATH, data, false)) {
        // Trim whitespace
        data.erase(0, data.find_first_not_of(" \n\r\t"));
        data.erase(data.find_last_not_of(" \n\r\t") + 1);
        
        if (!data.empty()) {
            std::wstring latest = std::wstring(data.begin(), data.end());
            outLatestVer = latest;
            return latest != CURR_VERSION;
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

void InstallUpdateAndRestart(const std::wstring& newExePath)
{
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    
    // Launch new EXE with --update flag: pman_new.exe --update <target_exe> <old_pid>
    std::wstring cmd = L"\"" + newExePath + L"\" --update \"" + selfPath + L"\" " + std::to_wstring(GetCurrentProcessId());
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // We must exit now to allow the overwrite
        ExitProcess(0);
    }
}

void FinalizeUpdate(const std::wstring& targetPath, DWORD oldPid)
{
    // 1. Wait for old process to exit
    HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, oldPid);
    if (hProc) {
        WaitForSingleObject(hProc, 10000); // Wait up to 10s
        CloseHandle(hProc);
    }
    
    // 2. Overwrite the old binary
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    
    bool success = false;
    for (int i = 0; i < 20; i++) { // Retry for 2 seconds
        if (CopyFileW(selfPath, targetPath.c_str(), FALSE)) {
            success = true;
            break;
        }
        Sleep(100);
    }
    
    // 3. Relaunch the original (now updated) binary
    if (success) {
        ShellExecuteW(nullptr, nullptr, targetPath.c_str(), L"/silent", nullptr, SW_SHOWDEFAULT);
    } else {
        MessageBoxW(nullptr, L"Failed to overwrite main executable.", L"Update Error", MB_OK | MB_ICONERROR);
    }
    
    // 4. Exit this temporary updater process
    ExitProcess(0);
}

