#include "types.h"
#include "constants.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "config.h"
#include "sysinfo.h"
#include "policy.h"
#include "events.h"
#include "tweaks.h"
#include "services.h"
#include <thread>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <objbase.h> // Fixed: Required for CoInitialize

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")

static void TerminateExistingInstances()
{
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);

    // RAII for Snapshot handle
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap.get(), &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, std::filesystem::path(self).filename().c_str()) == 0)
            {
                // RAII for Process handle
                UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID));
                if (hProc)
                {
                    if (pe.th32ProcessID != GetCurrentProcessId())
                    {
                        TerminateProcess(hProc.get(), 0);
                        WaitForSingleObject(hProc.get(), 3000);
                    }
                }
            }
        } while (Process32NextW(hSnap.get(), &pe));
    }
}

// Helper for initial reg read
static DWORD ReadCurrentPrioritySeparation()
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

static std::string GetModeDescription(DWORD val)
{
    if (val == VAL_GAME) return "GAME MODE (0x28) - Optimized for consistent frame times";
    else if (val == VAL_BROWSER) return "BROWSER MODE (0x26) - Optimized for multitasking responsiveness";
    else if (val == 0xFFFFFFFF) return "ERROR - Unable to read registry";
    else return "CUSTOM/UNKNOWN (0x" + std::to_string(val) + ")";
}

static bool IsTaskInstalled(const std::wstring& taskName)
{
    std::wstring cmd = L"schtasks /query /tn \"" + taskName + L"\"";
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi))
    {
        return false;
    }

	// Fix Use async wait with timeout to prevent startup hangs
    WaitForSingleObject(pi.hProcess, 3000); 
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
        
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return (exitCode == 0);
}

int wmain(int argc, wchar_t** argv)
{
    // Fix Silent Install/Uninstall Support
    bool uninstall = false;
    bool silent = false;

    for (int i = 1; i < argc; i++)
    {
        std::wstring arg = argv[i];
        if (arg == L"--uninstall" || arg == L"/uninstall") uninstall = true;
        else if (arg == L"/S" || arg == L"/s" || arg == L"/silent" || arg == L"-silent" || arg == L"/quiet") silent = true;
    }

    if (!uninstall)
    {
        g_hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is already running.", 
                    L"Priority Manager", MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        }
    }
    else
    {
        g_hMutex = nullptr;
    }

    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);

std::wstring taskName = std::filesystem::path(self).stem().wstring();

    if (uninstall)
    {
        TerminateExistingInstances();

		if (!IsTaskInstalled(taskName))
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is not currently installed.\nAny running instances have been stopped.", 
                    L"Priority Manager", MB_OK | MB_ICONWARNING);
            }
            if (g_hMutex) { CloseHandle(g_hMutex); g_hMutex = nullptr; }
            return 0;
        }

        std::wstring cmd = L"schtasks /delete /tn \"" + taskName + L"\" /f";
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }

        if (!silent)
        {
            MessageBoxW(nullptr, 
                L"Priority Manager has been successfully uninstalled.\nAny running instance has been stopped and the startup task removed.", 
                L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }

        if (g_hMutex) { CloseHandle(g_hMutex); g_hMutex = nullptr; }
        return 0;
    }

    bool taskExists = IsTaskInstalled(taskName);

    if (!taskExists)
    {
        std::wstring cmd = L"schtasks /create /tn \"" + taskName + L"\" /tr \"\\\"" + std::wstring(self) + L"\\\"\" /sc onlogon /rl highest /f";
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        BOOL created = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (created)
        {
            WaitForSingleObject(pi.hProcess, 10000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

		if (exitCode == 0)
            {
                if (!silent)
                    MessageBoxW(nullptr, L"Priority Manager installed successfully!\nIt will now run automatically at logon and is currently active.", L"Priority Manager", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                if (!silent)
                    MessageBoxW(nullptr, L"Failed to create startup task. Please run as Administrator.", L"Priority Manager - Error", MB_OK | MB_ICONWARNING);
                return 1;
            }
        }
        else
        {
            if (!silent)
                MessageBoxW(nullptr, L"Failed to launch schtasks. Please run as Administrator.", L"Priority Manager - Error", MB_OK | MB_ICONWARNING);
            return 1;
        }
    }

    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != nullptr)
    {
        ShowWindow(consoleWindow, SW_HIDE);
    }
    
    Log("=== Priority Manager Starting ===");
    Log("All Levels Implemented: Session-Scoped | Cooldown | Registry Guard | Graceful Shutdown | OS Detection | Anti-Interference");
    
    DetectOSCapabilities();
    DetectHybridCoreSupport();

    // Safety check: Restore services if they were left suspended from a crash
    if (g_caps.hasAdminRights && g_serviceManager.Initialize())
    {
        g_serviceManager.AddService(L"wuauserv", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
        g_serviceManager.AddService(L"BITS", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_START);
        
        // Check if services are suspended (shouldn't be at startup)
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scManager)
        {
            SC_HANDLE wuauserv = OpenServiceW(scManager, L"wuauserv", SERVICE_QUERY_STATUS | SERVICE_START);
            if (wuauserv)
            {
                SERVICE_STATUS status;
                if (QueryServiceStatus(wuauserv, &status))
                {
                    if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
                    {
                        Log("[STARTUP] WARNING: wuauserv was stopped/paused - attempting recovery");
                        StartServiceW(wuauserv, 0, nullptr);
                    }
                }
                CloseServiceHandle(wuauserv);
            }
            
            SC_HANDLE bits = OpenServiceW(scManager, L"BITS", SERVICE_QUERY_STATUS | SERVICE_START);
            if (bits)
            {
                SERVICE_STATUS status;
                if (QueryServiceStatus(bits, &status))
                {
                    if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
                    {
                        Log("[STARTUP] WARNING: BITS was stopped/paused - attempting recovery");
                        StartServiceW(bits, 0, nullptr);
                    }
                }
                CloseServiceHandle(bits);
            }
            
            CloseServiceHandle(scManager);
        }
    }

    LoadConfig();
    
    g_hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!g_hIocp)
    {
        Log("Failed to create IOCP: " + std::to_string(GetLastError()));
        return 1;
    }

    g_hShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, SHUTDOWN_EVENT_NAME);
    if (!g_hShutdownEvent)
    {
        Log("Failed to create shutdown event: " + std::to_string(GetLastError()));
    }
    
    std::thread configThread(IocpConfigWatcher);
    std::thread etwThread;
    if (g_caps.canUseEtw)
    {
        etwThread = std::thread(EtwThread);
    }
    else
    {
        Log("WARNING: ETW unavailable. Falling back to WinEvent (foreground) detection only.");
    }
    
    std::thread watchdogThread(AntiInterferenceWatchdog);
    
    CoInitialize(nullptr);
    
    HWINEVENTHOOK hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
                                         nullptr, WinEventProc, 0, 0,
                                         WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hook) 
    { 
        Log("SetWinEventHook failed: " + std::to_string(GetLastError()));
    }
    
    WNDCLASSW wc{}; 
    wc.lpfnWndProc = DefWindowProcW;
    wc.lpszClassName = L"PMHidden";
    RegisterClassW(&wc);
    
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"", 0, 0, 0, 0, 0, 
                              HWND_MESSAGE, nullptr, nullptr, nullptr);
    RegisterPowerNotifications(hwnd);
    
    Log("Background mode ready - monitoring foreground applications");
    
    DWORD currentSetting = ReadCurrentPrioritySeparation();
    if (currentSetting != 0xFFFFFFFF)
    {
        Log("Current system setting: " + GetModeDescription(currentSetting));
        g_originalRegistryValue = currentSetting;
        g_cachedRegistryValue.store(currentSetting);
    }
    else
    {
        Log("WARNING: Unable to read current registry setting");
    }
    
    MSG msg;
    while (g_running)
    {
        if (CheckForShutdownSignal())
        {
            PerformGracefulShutdown();
            break;
        }
        
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                g_running = false;
                break;
            }
            
            if (msg.message == WM_POWERBROADCAST && 
                msg.wParam == PBT_POWERSETTINGCHANGE)
            {
                g_reloadNow = true;
            }
            
            DispatchMessage(&msg);
        }
        
        if (g_reloadNow.exchange(false))
        {
            LoadConfig();
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        Sleep(100);
    }
    
    if (hook) UnhookWinEvent(hook);
    UnregisterPowerNotifications();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, nullptr);
    
    CoUninitialize();
    
    g_running = false;
    PostShutdown();
    
    if (configThread.joinable()) configThread.join();
    if (etwThread.joinable()) etwThread.join();
    if (watchdogThread.joinable()) watchdogThread.join();
    
    WaitForThreads();
    
    if (g_hIocp) CloseHandle(g_hIocp);
    if (g_hShutdownEvent) CloseHandle(g_hShutdownEvent);
    if (g_hMutex) CloseHandle(g_hMutex);
    
    Log("=== Priority Manager Stopped ===");
    return 0;
}