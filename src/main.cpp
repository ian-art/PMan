/*
 * MIT License
 *
 * Copyright (c) 2025 Ian Anthony R. Tancinco
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */


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
#include "restore.h"
#include <thread>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <objbase.h> // Fixed: Required for CoInitialize
#include <pdh.h>												
#include <shellapi.h> // Required for CommandLineToArgvW

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib") // For BITS monitoring


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

// Phase 4: Crash-Proof Registry Guard
static void RunRegistryGuard(DWORD targetPid, DWORD lowTime, DWORD highTime, DWORD originalVal)
{
	// 1. Wait for the main process to exit (crash, kill, or close)
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (hProcess)
    {
        // Verify process identity using creation time to prevent PID reuse
        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser))
        {
            // Check if the PID still belongs to the original instance
            if (ftCreation.dwLowDateTime == lowTime && ftCreation.dwHighDateTime == highTime)
            {
                WaitForSingleObject(hProcess, INFINITE);
            }
        }
        CloseHandle(hProcess);
    }
    // If OpenProcess failed, process is already gone, proceed to check.

    // 2. Check if registry was left in a modified state
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
        0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) == ERROR_SUCCESS)
    {
        DWORD currentVal = 0;
        DWORD size = sizeof(currentVal);
        if (RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, 
            reinterpret_cast<BYTE*>(&currentVal), &size) == ERROR_SUCCESS)
        {
            // If the value is different from the original default, restore it.
            if (currentVal != originalVal)
            {
                RegSetValueExW(key, L"Win32PrioritySeparation", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&originalVal), sizeof(originalVal));
                
                // Safe to log here as main process is dead
                Log("[GUARD] Main process crash detected. Registry Restored to 0x" + 
                    std::to_string(originalVal));
            }
        }
	RegCloseKey(key);
    } // End of Registry Check

    // 3. CRITICAL: Check and resume suspended services
    Log("[GUARD] Checking for stranded suspended services...");
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scManager) 
    {
        // Check BITS service
        SC_HANDLE bits = OpenServiceW(scManager, L"BITS", SERVICE_QUERY_STATUS | SERVICE_START);
        if (bits) 
        {
            SERVICE_STATUS status;
            if (QueryServiceStatus(bits, &status) && status.dwCurrentState == SERVICE_STOPPED)
            {
                // Check if it was stopped by us (last start time within last hour)
                // Heuristic: if stopped but not disabled, resume it
                DWORD configSize = 0;
                QueryServiceConfig(bits, NULL, 0, &configSize);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && configSize > 0)
                {
                    std::vector<BYTE> configBuffer(configSize);
                    LPQUERY_SERVICE_CONFIG config = reinterpret_cast<LPQUERY_SERVICE_CONFIG>(configBuffer.data());
                    if (QueryServiceConfig(bits, config, configSize, &configSize))
                    {
                        if (config->dwStartType != SERVICE_DISABLED)
                        {
                            StartServiceW(bits, 0, nullptr);
                            Log("[GUARD] BITS service was stopped - resumed");
                        }
                    }
                }
            }
            CloseServiceHandle(bits);
        }
        
        // Check Windows Update service
        SC_HANDLE wuauserv = OpenServiceW(scManager, L"wuauserv", SERVICE_QUERY_STATUS | SERVICE_START);
        if (wuauserv) 
        {
            SERVICE_STATUS status;
            if (QueryServiceStatus(wuauserv, &status) && status.dwCurrentState == SERVICE_STOPPED)
            {
                DWORD configSize = 0;
                QueryServiceConfig(wuauserv, NULL, 0, &configSize);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && configSize > 0)
                {
                    std::vector<BYTE> configBuffer(configSize);
                    LPQUERY_SERVICE_CONFIG config = reinterpret_cast<LPQUERY_SERVICE_CONFIG>(configBuffer.data());
                    if (QueryServiceConfig(wuauserv, config, configSize, &configSize))
                    {
                        if (config->dwStartType != SERVICE_DISABLED)
                        {
                            StartServiceW(wuauserv, 0, nullptr);
                            Log("[GUARD] wuauserv was stopped - resumed");
                        }
                    }
                }
            }
            CloseServiceHandle(wuauserv);
        }
        
        CloseServiceHandle(scManager);
    }
}

static void LaunchRegistryGuard(DWORD originalVal)
{
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    // Get current process creation time for identity verification
    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    GetProcessTimes(GetCurrentProcess(), &ftCreation, &ftExit, &ftKernel, &ftUser);

    // Pass PID, Creation Time (Low/High), and Original Value to the guard instance
    std::wstring cmd = L"\"" + std::wstring(selfPath) + L"\" --guard " + 
                       std::to_wstring(GetCurrentProcessId()) + L" " + 
                       std::to_wstring(ftCreation.dwLowDateTime) + L" " +
                       std::to_wstring(ftCreation.dwHighDateTime) + L" " +
                       std::to_wstring(originalVal);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW | DETACHED_PROCESS, 
                       nullptr, nullptr, &si, &pi))
    {
        // Guard process needs minimal resources (just waits in kernel)
        SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Log("[GUARD] Registry safety guard launched");
    }
    else
    {
        Log("[GUARD] Failed to launch safety guard: " + std::to_string(GetLastError()));
}
}

// Forward declaration for main program logic
int RunMainProgram(int argc, wchar_t** argv);

static NOTIFYICONDATAW g_nid = {};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
        g_nid.cbSize = sizeof(NOTIFYICONDATAW);
        g_nid.hWnd = hwnd;
        g_nid.uID = ID_TRAY_APP_ICON;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WM_TRAYICON;
        g_nid.hIcon = LoadIcon(GetModuleHandle(nullptr), MAKEINTRESOURCE(101)); 
        if (!g_nid.hIcon) g_nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wcscpy_s(g_nid.szTip, L"Priority Manager");
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            SetForegroundWindow(hwnd);
            HMENU hMenu = CreatePopupMenu();
            bool paused = g_userPaused.load();
			AppendMenuW(hMenu, MF_STRING | (paused ? MF_CHECKED : 0), ID_TRAY_PAUSE, paused ? L"Resume Protection" : L"Pause Protection");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_UPDATE, L"Check for Updates");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
            POINT pt; GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        }
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_TRAY_EXIT) {
            DestroyWindow(hwnd);
			} else if (LOWORD(wParam) == ID_TRAY_UPDATE) {
            std::thread([]{
                std::wstring latest;
                if (CheckForUpdates(latest)) {
                    int result = MessageBoxW(nullptr, 
                        (L"New version available: " + latest + L"\nUpdate now?").c_str(), 
                        L"Update Available", MB_YESNO | MB_ICONQUESTION);
                    
                    if (result == IDYES) {
                        wchar_t tempPath[MAX_PATH];
                        GetTempPathW(MAX_PATH, tempPath);
                        std::wstring dlPath = std::wstring(tempPath) + L"pman_new.exe";
                        
                        if (DownloadUpdate(dlPath)) {
                            InstallUpdateAndRestart(dlPath);
                        } else {
                            MessageBoxW(nullptr, L"Download failed.", L"Error", MB_OK | MB_ICONERROR);
                        }
                    }
                } else {
                    MessageBoxW(nullptr, L"No updates available.", L"Priority Manager", MB_OK | MB_ICONINFORMATION);
                }
            }).detach();

        } else if (LOWORD(wParam) == ID_TRAY_PAUSE) {
            bool p = !g_userPaused.load();
            g_userPaused.store(p);
            wcscpy_s(g_nid.szTip, p ? L"Priority Manager (Paused)" : L"Priority Manager");
            Shell_NotifyIconW(NIM_MODIFY, &g_nid);
            Log(p ? "[USER] Protection PAUSED." : "[USER] Protection RESUMED.");
            if (!p) g_reloadNow.store(true);
        }
        return 0;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nCmdShow);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Convert command line to argc/argv
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;
	
	// Check for Update Mode (Self-Update)
    if (argc >= 4 && std::wstring(argv[1]) == L"--update") {
        // argv[2] = target path, argv[3] = old pid
        FinalizeUpdate(argv[2], std::wcstoul(argv[3], nullptr, 10));
        return 0;
    }

    // Check for Guard Mode (Must be before Mutex check)
    if (argc >= 6 && (std::wstring(argv[1]) == L"--guard"))
    {
        DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        DWORD low = std::wcstoul(argv[3], nullptr, 10);
        DWORD high = std::wcstoul(argv[4], nullptr, 10);
        DWORD val = std::wcstoul(argv[5], nullptr, 10);
        RunRegistryGuard(pid, low, high, val);
        return 0;
    }

    // Fix Silent Install/Uninstall Support
    bool uninstall = false;
    bool silent = false;

	for (int i = 1; i < argc; i++)
    {
        std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h" || arg == L"/?")
        {
            MessageBoxW(nullptr, 
                L"Priority Manager (pman) v2.0.9.2025\n"
				L"by Ian Anthony R. Tancinco\n\n"
                L"Usage: pman.exe [OPTIONS]\n\n"
				L"Options:\n"
                L"  --help, -h, /?      Show this help message\n"
                L"  --uninstall         Stop instances and remove startup task\n"
                L"  --silent, /S         Run operations without message boxes\n"
                L"  --guard             (Internal) Registry safety guard\n\n"
                L"Automated Windows Priority & Affinity Manager",
                L"Priority Manager - Help", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        else if (arg == L"--uninstall" || arg == L"/uninstall") uninstall = true;
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
        // Add --guard /S flags to the scheduled task command
        std::wstring cmdStr = L"schtasks /create /tn \"" + taskName + L"\" /tr \"\\\"" + std::wstring(self) + L"\\\" --guard /S\" /sc onlogon /rl highest /f";
        
        // Fix CreateProcessW requires a mutable buffer
        std::vector<wchar_t> cmdBuf(cmdStr.begin(), cmdStr.end());
        cmdBuf.push_back(L'\0');

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        BOOL created = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
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
	
	Log("*********************************");
    Log("=== Priority Manager Starting ===");
    Log("All Levels Implemented: Session-Scoped | Cooldown | Registry Guard | Graceful Shutdown | OS Detection | Anti-Interference");
    
	// Initialize Performance Guardian
    g_perfGuardian.Initialize();

    // Initialize Smart Shell Booster
    g_explorerBooster.Initialize();

    DetectOSCapabilities();
    // Create restore point in background thread (non-blocking)
    std::thread restoreThread([]() {
        EnsureStartupRestorePoint();
    });
    restoreThread.detach(); // Don't block startup
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
    
    // Helper to pin thread to last physical core (away from games)
    auto PinBackgroundThread = [](std::thread& t) {
        if (g_physicalCoreCount > 2) {
            DWORD_PTR affinityMask = 1ULL << (g_physicalCoreCount - 1);
            SetThreadAffinityMask(t.native_handle(), affinityMask);
        }
    };
    
    std::thread configThread(IocpConfigWatcher);
    PinBackgroundThread(configThread);
    
    std::thread etwThread;
    if (g_caps.canUseEtw)
    {
        etwThread = std::thread(EtwThread);
        PinBackgroundThread(etwThread);
    }
    
    std::thread watchdogThread(AntiInterferenceWatchdog);
    PinBackgroundThread(watchdogThread);
    
    // FIX: Check return value (C6031)
    HRESULT hrInit = CoInitialize(nullptr);
    if (FAILED(hrInit)) {
        Log("[INIT] CoInitialize failed: " + std::to_string(hrInit));
    }
    
    HWINEVENTHOOK hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
                                         nullptr, WinEventProc, 0, 0,
                                         WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hook) 
    { 
        Log("SetWinEventHook failed: " + std::to_string(GetLastError()));
    }
    
	WNDCLASSW wc{}; 
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = L"PMHidden";
    RegisterClassW(&wc);
    
    // Parent must be nullptr (Top-level) for Tray Icon to receive events reliably
	HWND hwnd = CreateWindowW(wc.lpszClassName, L"PriorityManagerTray", 0, 0, 0, 0, 0, 
                              nullptr, nullptr, nullptr, nullptr);
    RegisterPowerNotifications(hwnd);
    
    // Register for Raw Input to track user activity (Keyboard & Mouse) for Explorer Booster
    RAWINPUTDEVICE Rid[2];
    // Keyboard
    Rid[0].usUsagePage = 0x01; 
    Rid[0].usUsage = 0x06; 
    Rid[0].dwFlags = RIDEV_INPUTSINK;   
    Rid[0].hwndTarget = hwnd;
    // Mouse
    Rid[1].usUsagePage = 0x01; 
    Rid[1].usUsage = 0x02; 
    Rid[1].dwFlags = RIDEV_INPUTSINK; 
    Rid[1].hwndTarget = hwnd;

    if (!RegisterRawInputDevices(Rid, 2, sizeof(Rid[0]))) {
        Log("[INIT] Raw Input registration failed: " + std::to_string(GetLastError()));
    } else {
        Log("[INIT] Raw Input registered for idle detection");
    }

    Log("Background mode ready - monitoring foreground applications");
    
    DWORD currentSetting = ReadCurrentPrioritySeparation();
    if (currentSetting != 0xFFFFFFFF)
    {
        Log("Current system setting: " + GetModeDescription(currentSetting));
        g_originalRegistryValue = currentSetting;
        g_cachedRegistryValue.store(currentSetting);
        
        // Launch Crash-Proof Guard
        if (g_restoreOnExit.load())
        {
            LaunchRegistryGuard(currentSetting);
        }
    }
    else
    {
        Log("WARNING: Unable to read current registry setting");
	}
    
	MSG msg;
    // FIX: Use 64-bit time tracking to prevent overflow issues (C28159)
    static uint64_t g_lastExplorerPollMs = 0;

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
            
            if (msg.message == WM_INPUT) 
            {
                // Signal user activity to Smart Explorer Booster
                g_explorerBooster.OnUserActivity();
                DefWindowProc(msg.hwnd, msg.message, msg.wParam, msg.lParam);
            }
            else if (msg.message == WM_POWERBROADCAST)
            {
                if (msg.wParam == PBT_APMQUERYSUSPEND || msg.wParam == PBT_APMSUSPEND)
                {
                    Log("System suspending - pausing operations to prevent memory corruption");
                    g_isSuspended.store(true);
                }
                else if (msg.wParam == PBT_APMRESUMEAUTOMATIC || msg.wParam == PBT_APMRESUMESUSPEND)
                {
                    Log("System resumed - waiting 5s for kernel stability");
                    Sleep(5000); 
                    g_isSuspended.store(false);
                }
                else if (msg.wParam == PBT_POWERSETTINGCHANGE)
                {
                    g_reloadNow = true;
                }
            }
            
            DispatchMessage(&msg);
        }
        
		if (g_reloadNow.exchange(false))
        {
            // Allow file system to settle (fixes empty-read race conditions with Notepad++/UAC)
            Sleep(250);
            LoadConfig();
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        // Wait for messages with timeout - efficient polling that doesn't spin CPU
        // Use MsgWaitForMultipleObjects to stay responsive to inputs/shutdown while waiting
        DWORD waitResult = MsgWaitForMultipleObjects(1, &g_hShutdownEvent, FALSE, 100, QS_ALLINPUT);
        
        // Process explorer boost tick only if we timed out (no messages to process)
        // This prevents calling OnTick() during active user input, reducing overhead
		if (waitResult == WAIT_TIMEOUT)
        {
            // Calculate adaptive polling interval based on idle state
            // FIX: Use GetTickCount64 (C28159)
            uint64_t now = GetTickCount64();
            uint64_t idleDurationMs = now - g_explorerBooster.GetLastUserActivity();
            uint32_t thresholdMs = g_explorerBooster.GetIdleThreshold();
            
            // Adaptive poll rate: poll faster when approaching idle threshold (within 5s)
            bool approachingIdle = (idleDurationMs > 0 && idleDurationMs < thresholdMs && 
                                   idleDurationMs > (thresholdMs - 5000));
            uint32_t pollIntervalMs = approachingIdle ? 250 : 2000;

			// Rate limit the tick calls to prevent CPU spinning
            if ((now - g_lastExplorerPollMs) >= pollIntervalMs) {
                g_explorerBooster.OnTick();
                // FIX: Drive Performance Guardian for non-ETW games (DX9)
                g_perfGuardian.OnPerformanceTick();
                g_lastExplorerPollMs = now;
            }
        }
    }
    
	if (hook) UnhookWinEvent(hook);
    
    // FIX: Explicitly unregister raw input devices (Renamed to RidCleanup to avoid redefinition error)
    RAWINPUTDEVICE RidCleanup[2] = {};
    RidCleanup[0].usUsagePage = 0x01; RidCleanup[0].usUsage = 0x06; RidCleanup[0].dwFlags = RIDEV_REMOVE; RidCleanup[0].hwndTarget = nullptr;
    RidCleanup[1].usUsagePage = 0x01; RidCleanup[1].usUsage = 0x02; RidCleanup[1].dwFlags = RIDEV_REMOVE; RidCleanup[1].hwndTarget = nullptr;
    RegisterRawInputDevices(RidCleanup, 2, sizeof(RAWINPUTDEVICE));

    UnregisterPowerNotifications();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, nullptr);
    
	CoUninitialize();
    
	g_running = false;
    g_explorerBooster.Shutdown();
    
    // Signal threads to wake up/stop
    if (g_hShutdownEvent) SetEvent(g_hShutdownEvent); // Wakes Watchdog immediately
    StopEtwSession(); // Unblocks EtwThread (ProcessTrace returns)
    PostShutdown(); // Wakes IocpConfigWatcher
    
    if (configThread.joinable()) configThread.join();
    if (etwThread.joinable()) etwThread.join();
    if (watchdogThread.joinable()) watchdogThread.join();
    
    WaitForThreads();
    
	if (g_hIocp && g_hIocp != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hIocp);
        g_hIocp = nullptr;
    }

    if (g_hShutdownEvent && g_hShutdownEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hShutdownEvent);
        g_hShutdownEvent = nullptr;
    }

    if (g_hMutex && g_hMutex != INVALID_HANDLE_VALUE) {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        g_hMutex = nullptr;
    }
    
    Log("=== Priority Manager Stopped ===");
    return 0;
}