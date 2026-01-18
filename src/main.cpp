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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
#include "services_watcher.h"
#include "restore.h"
#include "static_tweaks.h"
#include "memory_optimizer.h"
#include "network_monitor.h"
#include "input_guardian.h"
#include <thread>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <objbase.h> // Fixed: Required for CoInitialize
#include <powrprof.h>
#include <pdh.h>
#include <shellapi.h> // Required for CommandLineToArgvW
#include <commctrl.h> // For Edit Control in Live Log
#include <fstream>    // Required for std::ofstream
#include <deque>
#include <mutex>
#include <condition_variable>
#include <functional>

#pragma comment(lib, "PowrProf.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib") // For BITS monitoring
#pragma comment(lib, "Gdi32.lib") // Required for CreateFontW/DeleteObject
#pragma comment(lib, "Comctl32.lib") // Required for TaskDialog

// Force Linker to embed Manifest for Visual Styles (Required for TaskDialog)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// GLOBAL VARIABLE
HINSTANCE g_hInst = nullptr;
static UINT g_wmTaskbarCreated = 0;
HWND g_hLogWindow = nullptr; // Handle for Live Log Window
static std::atomic<bool> g_isCheckingUpdate{false};
static GUID* g_pSleepScheme = nullptr;

// Async launcher to prevent UI thread blocking
void LaunchProcessAsync(const std::wstring& cmd, std::function<void(DWORD)> callback) {
    std::thread([cmd, callback]{
        STARTUPINFOW si{sizeof(si)};
        PROCESS_INFORMATION pi{};
        // Create mutable buffer for CreateProcessW
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(0);

        if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {

            // RAII Adoption
            UniqueHandle hProc(pi.hProcess);
            UniqueHandle hThread(pi.hThread);

            WaitForSingleObject(hProc.get(), 5000);
            DWORD exitCode = 0;
            GetExitCodeProcess(hProc.get(), &exitCode);
            // Handles closed automatically
            if (callback) callback(exitCode);
        } else {
            if (callback) callback(GetLastError());
        }
    }).detach();
}

// --- Background Worker for Async Tasks ---
static std::thread g_backgroundWorker;
static std::mutex g_backgroundQueueMtx;
static std::deque<std::function<void()>> g_backgroundTasks;
static std::condition_variable g_backgroundCv;
static std::atomic<bool> g_backgroundRunning{ true };

static void BackgroundWorkerThread() {
    while (g_backgroundRunning.load()) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(g_backgroundQueueMtx);
            g_backgroundCv.wait(lock, [] {
                return !g_backgroundTasks.empty() || !g_backgroundRunning.load();
            });

            if (!g_backgroundRunning.load() && g_backgroundTasks.empty()) break;

            if (!g_backgroundTasks.empty()) {
                task = std::move(g_backgroundTasks.front());
                g_backgroundTasks.pop_front();
            }
        }
        if (task) task();
    }
}

// --- Helper: Detect External Editors (Notepad++, VS Code, etc.) ---
static std::wstring GetRegisteredAppPath(const wchar_t* exeName) {
    const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    wchar_t buffer[MAX_PATH];
    
    for (HKEY root : roots) {
        HKEY hKey;
        std::wstring keyPath = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") + exeName;
        if (RegOpenKeyExW(root, keyPath.c_str(), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD size = sizeof(buffer);
            // Default value of the key contains the full path to the executable
            if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return buffer;
            }
            RegCloseKey(hKey);
        }
    }
    return L"";
}

// --- Helper: Find Line Number of Section Header ---
static int GetConfigLineNumber(const std::wstring& sectionHeader) {
    std::filesystem::path path = GetLogPath() / CONFIG_FILENAME;
    std::wifstream file(path);
    if (!file) return 0;

    std::wstring line;
    int lineNum = 1;
    while (std::getline(file, line)) {
        if (line.find(sectionHeader) != std::wstring::npos) {
            return lineNum;
        }
        lineNum++;
    }
    return 0;
}

// --- Helper: Open File in Default or Specific Editor ---
static void OpenFileInEditor(const std::wstring& filename, const std::wstring& forcedEditor = L"", int jumpToLine = 0) {
    std::filesystem::path path = GetLogPath() / filename;
    // Ensure file exists to prevent error
    if (!std::filesystem::exists(path)) {
        std::ofstream(path) << ""; // Create empty if missing
    }

	// 1. Priority: Custom Editor (Notepad++, VS Code, etc.)
    if (!forcedEditor.empty()) {
        std::wstring params;

        // Format command line args based on detected editor
        if (jumpToLine > 0) {
            std::wstring lowerEditor = forcedEditor;
            std::transform(lowerEditor.begin(), lowerEditor.end(), lowerEditor.begin(), ::towlower);

            if (lowerEditor.find(L"notepad++.exe") != std::wstring::npos) {
                // Notepad++: -n123 "path"
                params = L"-n" + std::to_wstring(jumpToLine) + L" \"" + path.wstring() + L"\"";
            } else if (lowerEditor.find(L"code.exe") != std::wstring::npos) {
                // VS Code: -g "path:123"
                params = L"-g \"" + path.wstring() + L":" + std::to_wstring(jumpToLine) + L"\"";
            } else if (lowerEditor.find(L"sublime_text.exe") != std::wstring::npos) {
                // Sublime: "path:123"
                params = L"\"" + path.wstring() + L":" + std::to_wstring(jumpToLine) + L"\"";
            } else {
                params = L"\"" + path.wstring() + L"\"";
            }
        } else {
            params = L"\"" + path.wstring() + L"\"";
        }

        HINSTANCE res = ShellExecuteW(nullptr, L"open", forcedEditor.c_str(), params.c_str(), nullptr, SW_SHOW);
        if ((intptr_t)res > 32) return; // Success
    }

    // 2. Fallback: Force "Run as Administrator" on default Notepad
    // This solves the "Can't save in ProgramData" issue.
    // We target "notepad.exe" explicitly to attach the "runas" verb.
    std::wstring params = L"\"" + path.wstring() + L"\"";
    HINSTANCE res = ShellExecuteW(nullptr, L"runas", L"notepad.exe", params.c_str(), nullptr, SW_SHOW);
    
    // 3. Last Resort: Generic "Open" (Stripped Windows / No Notepad)
    // If Admin Notepad failed (User cancelled UAC, or notepad.exe is missing in stripped OS)
    if ((intptr_t)res <= 32) {
        // Try to open with WHATEVER is registered for .txt/.ini (could be WordPad, etc.)
        res = ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOW);
        
        // 4. Absolute Failure: No application found
        if ((intptr_t)res <= 32) {
             MessageBoxW(nullptr, 
                 L"Unable to open configuration file.\n\n"
                 L"No text editor was found on this system, or the operation was cancelled.",
                 L"Editor Error", MB_OK | MB_ICONERROR);
        }
    }
}

// --- Live Log Viewer Window Class ---
class LogViewer {
public:
    static void Register(HINSTANCE hInst) {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = Proc;
        wc.hInstance = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"PManLogViewer";
        wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(101));
        RegisterClassW(&wc);
    }

    static void Show(HWND hOwner) {
        if (g_hLogWindow) {
            if (IsIconic(g_hLogWindow)) ShowWindow(g_hLogWindow, SW_RESTORE);
            SetForegroundWindow(g_hLogWindow);
            return;
        }
        g_hLogWindow = CreateWindowW(L"PManLogViewer", L"Priority Manager - Live Log",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
            hOwner, nullptr, g_hInst, nullptr);
        ShowWindow(g_hLogWindow, SW_SHOW);
		// [FIX] Force flush buffered logs to disk immediately when Viewer opens.
        // This ensures the viewer has a file to read even if no new logs occur.
        FlushLogger();
    }

private:
    static LRESULT CALLBACK Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        static HWND hEdit;
        static HFONT hFont;
        static UINT_PTR hTimer;
        static std::streampos lastPos = 0;

        switch (uMsg) {
        case WM_CREATE: {
            hEdit = CreateWindowW(L"EDIT", nullptr,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                0, 0, 0, 0, hwnd, (HMENU)1, g_hInst, nullptr);
            
            hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
			SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

            // Fix: Increase text limit from default 32KB to Max (approx 2GB) to prevent truncation
            SendMessageW(hEdit, EM_LIMITTEXT, 0, 0);

            hTimer = SetTimer(hwnd, 1, 500, nullptr);
            UpdateLog(hEdit, lastPos);
            return 0;
        }
        case WM_SIZE: {
            RECT rc; GetClientRect(hwnd, &rc);
            MoveWindow(hEdit, 0, 0, rc.right, rc.bottom, TRUE);
            return 0;
        }
		case WM_TIMER:
        case WM_LOG_UPDATED: // Handle push notification for zero-latency updates
            UpdateLog(hEdit, lastPos);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, hTimer);
            DeleteObject(hFont);
            g_hLogWindow = nullptr;
			lastPos = 0; 
            return 0;
        }
        // Fix: Explicitly use DefWindowProcW to prevent title truncation ("P") in non-Unicode builds
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

    static void UpdateLog(HWND hEdit, std::streampos& lastPos) {
        std::filesystem::path logPath = GetLogPath() / L"log.txt";
        
        HANDLE hFile = CreateFileW(logPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE) return;

        LARGE_INTEGER size;
        GetFileSizeEx(hFile, &size);

        if (size.QuadPart < lastPos) lastPos = 0;

        if (size.QuadPart > lastPos) {
            DWORD bytesToRead = (DWORD)(size.QuadPart - lastPos);
            if (bytesToRead > 65536 && lastPos == 0) {
                lastPos = size.QuadPart - 65536;
                bytesToRead = 65536;
            }

            std::vector<char> buffer(bytesToRead + 1);
            LARGE_INTEGER move; move.QuadPart = lastPos;
            SetFilePointerEx(hFile, move, nullptr, FILE_BEGIN);
            
            DWORD bytesRead = 0;
            if (ReadFile(hFile, buffer.data(), bytesToRead, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                
                int wlen = MultiByteToWideChar(CP_ACP, 0, buffer.data(), bytesRead, nullptr, 0);
                std::vector<wchar_t> wBuffer(wlen + 1);
                MultiByteToWideChar(CP_ACP, 0, buffer.data(), bytesRead, wBuffer.data(), wlen);
                wBuffer[wlen] = L'\0';

				// Append text
                // Fix C4245: Cast -1 to WPARAM (UINT_PTR) explicitly
                SendMessageW(hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1); // Move to end
                SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)wBuffer.data());
                lastPos += bytesRead;
            }
        }
        CloseHandle(hFile);
    }
};

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

    UniqueHandle hProc(pi.hProcess);
    UniqueHandle hThread(pi.hThread);

    // Fix Use async wait with timeout to prevent startup hangs
    WaitForSingleObject(hProc.get(), 3000); 
    DWORD exitCode = 0;
    GetExitCodeProcess(hProc.get(), &exitCode);

return (exitCode == 0);
}

static int GetStartupMode(const std::wstring& taskName)
{
    if (!IsTaskInstalled(taskName)) return 0; // Disabled

    // Check if task has --paused argument by querying XML definition
    std::wstring cmd = L"cmd /c schtasks /query /tn \"" + taskName + L"\" /xml | findstr /C:\"--paused\"";
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        UniqueHandle hProc(pi.hProcess);
        UniqueHandle hThread(pi.hThread);

        WaitForSingleObject(hProc.get(), 3000);
        DWORD exitCode = 1;
        GetExitCodeProcess(hProc.get(), &exitCode);

        // findstr returns 0 if found, 1 if not found
        return (exitCode == 0) ? 2 : 1; // 2=Passive, 1=Active
    }
    return 1; // Default to Active if check fails but task exists
}

// [MOVED] Registry Guard implementation moved to restore.cpp

// Forward declaration for main program logic
int RunMainProgram(int argc, wchar_t** argv);

static NOTIFYICONDATAW g_nid = {};

// Helper for enhanced modern dialogs (Vista+)
static int ShowRichDialog(HWND hwnd, const std::wstring& title, const std::wstring& header, 
                          const std::wstring& content, PCWSTR icon, int buttons = TDCBF_OK_BUTTON)
{
    // 1. Try Modern TaskDialog (Vista+) via Dynamic Loading
    // Using a block scope ensures we don't skip initializations if we fall through
    {
        // Use LoadLibrary instead of static linking to avoid "Ordinal 344" errors on older/incompatible systems
        HMODULE hComctl32 = LoadLibraryExW(L"Comctl32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hComctl32) 
        {
            // Define prototype manually to avoid linking dependency on Comctl32.lib
            typedef HRESULT (WINAPI *P_TaskDialog)(HWND, HINSTANCE, PCWSTR, PCWSTR, PCWSTR, int, PCWSTR, int*);
            P_TaskDialog pTaskDialog = (P_TaskDialog)GetProcAddress(hComctl32, "TaskDialog");

            if (pTaskDialog) 
            {
                int pressed = 0;
                HRESULT hr = pTaskDialog(hwnd, g_hInst, title.c_str(), header.c_str(), content.c_str(), 
                                        buttons, icon, &pressed);
                
                FreeLibrary(hComctl32);
                
                if (SUCCEEDED(hr)) {
                    return pressed;
                }
            }
            else
            {
                FreeLibrary(hComctl32);
            }
        }
    }

    // 2. Fallback to MessageBoxW (Legacy / Safety)
    UINT uType = (buttons & TDCBF_YES_BUTTON) ? MB_YESNO : MB_OK;
    if (icon == TD_ERROR_ICON) uType |= MB_ICONERROR;
    else if (icon == TD_WARNING_ICON) uType |= MB_ICONWARNING;
    else uType |= MB_ICONINFORMATION;
    
    std::wstring fullMsg = header + L"\n\n" + content;
    return MessageBoxW(hwnd, fullMsg.c_str(), title.c_str(), uType);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Re-add icon if Explorer restarts (TaskbarCreated message)
    if (g_wmTaskbarCreated && uMsg == g_wmTaskbarCreated)
    {
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        return 0;
    }

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
            
            // Detect best available editor (Priority: Notepad++ -> VS Code -> Sublime)
            std::wstring editorPath, editorName;
            if ((editorPath = GetRegisteredAppPath(L"notepad++.exe")) != L"")      editorName = L" [Notepad++]";
            else if ((editorPath = GetRegisteredAppPath(L"Code.exe")) != L"")      editorName = L" [VS Code]";
            else if ((editorPath = GetRegisteredAppPath(L"sublime_text.exe")) != L"") editorName = L" [Sublime]";

            HMENU hMenu = CreatePopupMenu();
            bool paused = g_userPaused.load();

            // 1. Dashboards Submenu
            HMENU hDashMenu = CreatePopupMenu();
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_LIVE_LOG, L"Live Log Viewer");
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_OPEN_DIR, L"Open Log Folder");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDashMenu, L"Monitor & Logs");

			// 2. Configuration Submenu
            HMENU hConfigMenu = CreatePopupMenu();
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_CONFIG, (L"Edit Config (config.ini)" + editorName).c_str());
            AppendMenuW(hConfigMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_GAMES, (L"Edit Games List" + editorName).c_str());
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_BROWSERS, (L"Edit Browsers List" + editorName).c_str());
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_VIDEO_PLAYERS, (L"Edit Video Players List" + editorName).c_str());
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_IGNORED, (L"Edit Ignored Processes" + editorName).c_str());
            AppendMenuW(hConfigMenu, MF_STRING, ID_TRAY_EDIT_LAUNCHERS, (L"Edit Custom Launchers" + editorName).c_str());
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hConfigMenu, L"Configuration");

            // 3. Controls Submenu
            HMENU hControlMenu = CreatePopupMenu();
            AppendMenuW(hControlMenu, MF_STRING | (paused ? MF_CHECKED : 0), ID_TRAY_PAUSE, paused ? L"Resume Activity" : L"Pause Activity");
            
            // Pause Idle Optimization (prevent CPU limiting during background tasks)
            bool idlePaused = g_pauseIdle.load();
            AppendMenuW(hControlMenu, MF_STRING | (idlePaused ? MF_CHECKED : 0), ID_TRAY_PAUSE_IDLE, L"Passive Mode");

            AppendMenuW(hControlMenu, MF_STRING, ID_TRAY_APPLY_TWEAKS, L"Boost System Now");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hControlMenu, MF_STRING, ID_TRAY_REFRESH_GPU, L"Refresh GPU");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hControlMenu, L"Controls");

			AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

			// 4. Global Actions
            wchar_t self[MAX_PATH];
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();

            // Cache startup mode to avoid blocking UI with GetStartupMode()
            static int cachedMode = -1;
            static uint64_t lastCheck = 0;
            uint64_t now = GetTickCount64();

            if (cachedMode == -1 || (now - lastCheck > 5000)) {
                // Fast check (non-blocking if cached or assume previous)
                // Real update happens in background if needed, here we accept slight staleness for UI responsiveness
                cachedMode = GetStartupMode(taskName); 
                lastCheck = now;
            }
            int startupMode = cachedMode;

            HMENU hStartupMenu = CreatePopupMenu();
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 0 ? MF_CHECKED : 0), ID_TRAY_STARTUP_DISABLED, L"Disabled (Manual Start)");
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 1 ? MF_CHECKED : 0), ID_TRAY_STARTUP_ACTIVE,   L"Enabled (Active Optimization)");
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 2 ? MF_CHECKED : 0), ID_TRAY_STARTUP_PASSIVE,  L"Enabled (Standby Mode)");
            
			AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hStartupMenu, L"Startup Behavior");
            
            // 5. Help Submenu
            HMENU hHelpMenu = CreatePopupMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_HELP_USAGE, L"Help");
            AppendMenuW(hHelpMenu, MF_STRING | (g_isCheckingUpdate.load() ? MF_GRAYED : 0), ID_TRAY_UPDATE, L"Check for Updates");
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_ABOUT, L"About");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"Help");
            
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SUPPORT, L"Support PMan \u2764\U0001F97A");
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");

            POINT pt; GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            
            DestroyMenu(hControlMenu);
            DestroyMenu(hConfigMenu);
            DestroyMenu(hDashMenu);
            DestroyMenu(hHelpMenu);
            DestroyMenu(hMenu);
        }
        return 0;

    case WM_COMMAND:
    {
        DWORD wmId = LOWORD(wParam);
        
        // --- New Handlers ---
        if (wmId == ID_TRAY_LIVE_LOG) {
            LogViewer::Show(hwnd);
        }
        else if (wmId == ID_TRAY_OPEN_DIR) {
            ShellExecuteW(nullptr, L"open", GetLogPath().c_str(), nullptr, nullptr, SW_SHOW);
        }
		else if (wmId == ID_TRAY_EDIT_CONFIG) {
            // Re-detect to ensure we have the path (or cache it in a broader scope, but this is safe)
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            OpenFileInEditor(CONFIG_FILENAME, path);
        }
		else if (wmId == ID_TRAY_EDIT_GAMES) {
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            
            int line = GetConfigLineNumber(L"[games]");
            OpenFileInEditor(CONFIG_FILENAME, path, line); 
        }
        else if (wmId == ID_TRAY_EDIT_BROWSERS) {
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            
            int line = GetConfigLineNumber(L"[browsers]");
            OpenFileInEditor(CONFIG_FILENAME, path, line); 
        }
        else if (wmId == ID_TRAY_EDIT_VIDEO_PLAYERS) {
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            
            int line = GetConfigLineNumber(L"[video_players]");
            OpenFileInEditor(CONFIG_FILENAME, path, line); 
        }
		else if (wmId == ID_TRAY_EDIT_IGNORED) {
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            OpenFileInEditor(IGNORED_PROCESSES_FILENAME, path, 0);
        }
		else if (wmId == ID_TRAY_EDIT_LAUNCHERS) {
            std::wstring path = GetRegisteredAppPath(L"notepad++.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"Code.exe");
            if (path.empty()) path = GetRegisteredAppPath(L"sublime_text.exe");
            OpenFileInEditor(CUSTOM_LAUNCHERS_FILENAME, path, 0);
        }
		// --- End New Handlers ---

        else if (wmId == ID_TRAY_STARTUP_DISABLED) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            ShellExecuteW(nullptr, L"runas", L"schtasks.exe", (L"/delete /tn \"" + taskName + L"\" /f").c_str(), nullptr, SW_HIDE);
        }
        else if (wmId == ID_TRAY_STARTUP_ACTIVE || wmId == ID_TRAY_STARTUP_PASSIVE) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            
            // Base arguments: Silent only. Passive mode adds --paused
            std::wstring args = L" /S";
            if (wmId == ID_TRAY_STARTUP_PASSIVE) args += L" --paused";

            std::wstring params = L"/create /tn \"" + taskName + L"\" /tr \"\\\"" + std::wstring(self) + L"\\\"" + args + L"\" /sc onlogon /rl highest /f";
            ShellExecuteW(nullptr, L"runas", L"schtasks.exe", params.c_str(), nullptr, SW_HIDE);
        }
        else if (wmId == ID_TRAY_EXIT) {
            DestroyWindow(hwnd);
        } 
        else if (wmId == ID_TRAY_ABOUT) {
            std::wstring version = GetCurrentExeVersion();
            std::wstring header = L"Priority Manager " + version;
            std::wstring content = L"Copyright \251 2025-2026 Ian Anthony R. Tancinco\n\n"
                                   L"Automated Windows Priority & Affinity Manager\n"
                                   L"Designed for high-performance low-latency gaming.";
            
            ShowRichDialog(hwnd, L"About Priority Manager", header, content, TD_INFORMATION_ICON);
        }
		else if (wmId == ID_TRAY_SUPPORT) {
            ShellExecuteW(nullptr, L"open", SUPPORT_URL, nullptr, nullptr, SW_SHOWNORMAL);
        }
        else if (wmId == ID_TRAY_HELP_USAGE) {
            std::wstring version = GetCurrentExeVersion();
            std::wstring msg;
            msg.reserve(512);
            msg += L"Priority Manager (pman) v" + version + L"\n";
            msg += L"by Ian Anthony R. Tancinco\n\n";
            msg += L"Usage: pman.exe [OPTIONS]\n\n";
            msg += L"Options:\n";
            msg += L"  --help, -h, /?      Show this help message\n";
            msg += L"  --uninstall         Stop instances and remove startup task\n";
            msg += L"  --silent, /S         Run operations without message boxes\n";
            msg += L"  --guard             (Internal) Registry safety guard\n\n";
            msg += L"Automated Windows Priority & Affinity Manager";
            
            ShowRichDialog(hwnd, L"Priority Manager Help", L"Command Line Usage", msg, TD_INFORMATION_ICON);
        }
        else if (wmId == ID_TRAY_UPDATE) {
            OpenUpdatePage();
        }
        else if (wmId == ID_TRAY_APPLY_TWEAKS) {
            int result = MessageBoxW(hwnd, 
                L"This will apply a set of one-time system optimizations.\n\n"
                L"Note: Reboot system for the changes to take effect.\n\n"
                L"Continue?", 
                L"Apply System Tweaks", MB_YESNO | MB_ICONQUESTION);

            if (result == IDYES) {
                std::thread([]{
                    ApplyStaticTweaks();
                    MessageBoxW(nullptr, L"System tweaks have been applied successfully.", L"Priority Manager", MB_OK | MB_ICONINFORMATION);
                }).detach();
            }
        } 
        else if (wmId == ID_TRAY_REFRESH_GPU) {
            // Simulate Win+Ctrl+Shift+B to reset graphics driver
            INPUT inputs[8] = {};

            // Press
            inputs[0].type = INPUT_KEYBOARD; inputs[0].ki.wVk = VK_LCONTROL;
            inputs[1].type = INPUT_KEYBOARD; inputs[1].ki.wVk = VK_LSHIFT;
            inputs[2].type = INPUT_KEYBOARD; inputs[2].ki.wVk = VK_LWIN;
            inputs[3].type = INPUT_KEYBOARD; inputs[3].ki.wVk = 0x42; // 'B' key

            // Release (Reverse order)
            inputs[4] = inputs[3]; inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[5] = inputs[2]; inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[6] = inputs[1]; inputs[6].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[7] = inputs[0]; inputs[7].ki.dwFlags = KEYEVENTF_KEYUP;

            if (SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT)) == ARRAYSIZE(inputs)) {
                Log("[USER] GPU Driver Refresh triggered manually.");
            } else {
                Log("[ERROR] Failed to send GPU refresh keystrokes: " + std::to_string(GetLastError()));
            }
        }
        else if (wmId == ID_TRAY_PAUSE) {
            bool p = !g_userPaused.load();
            g_userPaused.store(p);
            wcscpy_s(g_nid.szTip, p ? L"Priority Manager (Paused)" : L"Priority Manager");
            Shell_NotifyIconW(NIM_MODIFY, &g_nid);
            Log(p ? "[USER] Protection PAUSED." : "[USER] Protection RESUMED.");
            if (!p) g_reloadNow.store(true);
        }
        else if (wmId == ID_TRAY_PAUSE_IDLE) {
            bool p = !g_pauseIdle.load();
            g_pauseIdle.store(p);
            Log(p ? "[USER] Idle Optimization PAUSED (CPU Limiting Disabled)." : "[USER] Idle Optimization RESUMED.");
            
            // Immediate effect: If we just paused, force the Idle Manager to think we are active
            // This restores all parked cores instantly.
            if (p) {
                g_idleAffinityMgr.OnIdleStateChanged(false); 
            }
        }
        return 0;
    } // End of WM_COMMAND Block

    case WM_DEVICECHANGE:
        // Invalidate cache on hardware/topology changes
        if (wParam == 0x0018 /* DBT_CONFIGCHANGED */) {
            Log("[HARDWARE] System configuration changed. Scheduling cache invalidation.");
            g_reloadNow.store(true);
        }
        return TRUE;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

int wmain(int argc, wchar_t* argv[])
{
    // Initialize Telemetry-Safe Logger
    InitLogger();

	// 1. Initialize Global Instance Handle (Required for Tray Icon)
    g_hInst = GetModuleHandle(nullptr);

    // Register UI Classes
    LogViewer::Register(g_hInst);

    // Register system-wide message for Taskbar recreation detection
    g_wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    // 2. Hide Console Window immediately (Restored logic for Console Subsystem)
    // This is required because /SUBSYSTEM:CONSOLE always spawns a window initially.
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != nullptr)
    {
        ShowWindow(consoleWindow, SW_HIDE);
    }

    // 3. argc/argv are provided directly by wmain, no conversion needed.

    // Check for Update Mode (Self-Update)
    if (argc >= 4 && std::wstring(argv[1]) == L"--update") {
        return 0;
    }

    // Check for Guard Mode (Must be before Mutex check)
    // argc count increased to 7 to account for Power GUID
    if (argc >= 7 && (std::wstring(argv[1]) == L"--guard"))
    {
        DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        DWORD low = std::wcstoul(argv[3], nullptr, 10);
        DWORD high = std::wcstoul(argv[4], nullptr, 10);
        DWORD val = std::wcstoul(argv[5], nullptr, 10);
        std::wstring powerScheme = argv[6];
        
        RunRegistryGuard(pid, low, high, val, powerScheme);
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
            std::wstring version = GetCurrentExeVersion();
            std::wstring msg;
            msg.reserve(512); // Pre-allocate to prevent reallocation fragmentation
            msg += L"Priority Manager (pman) v" + version + L"\n";
            msg += L"by Ian Anthony R. Tancinco\n\n";
            msg += L"Usage: pman.exe [OPTIONS]\n\n";
            msg += L"Options:\n";
            msg += L"  --help, -h, /?      Show this help message\n";
            msg += L"  --uninstall         Stop instances and remove startup task\n";
            msg += L"  --silent, /S         Run operations without message boxes\n";
            msg += L"  --guard             (Internal) Registry safety guard\n\n";
            msg += L"Automated Windows Priority & Affinity Manager";

            MessageBoxW(nullptr, msg.c_str(), L"Priority Manager - Help", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
		else if (arg == L"--uninstall" || arg == L"/uninstall") uninstall = true;
        else if (arg == L"/S" || arg == L"/s" || arg == L"/silent" || arg == L"-silent" || arg == L"/quiet") silent = true;
        else if (arg == L"--paused") g_userPaused.store(true);
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
        // Add /S flag (Silent) to the scheduled task command
        std::wstring cmdStr = L"schtasks /create /tn \"" + taskName + L"\" /tr \"\\\"" + std::wstring(self) + L"\\\" /S\" /sc onlogon /rl highest /f";
        
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

    // Console was hidden at startup.
	
	Log("*********************************");
    Log("=== Priority Manager Starting ===");
    Log("All Levels Implemented: Session-Scoped | Cooldown | Registry Guard | Graceful Shutdown | OS Detection | Anti-Interference");
    
	// Initialize Performance Guardian
    g_perfGuardian.Initialize();

    // Initialize Smart Shell Booster
    g_explorerBooster.Initialize();

    // Initialize Input Responsiveness Guard
    g_inputGuardian.Initialize();

	// Initialize Smart Memory Optimizer
    g_memoryOptimizer.Initialize();

	// Initialize Service Watcher
    ServiceWatcher::Initialize();

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
		/*
        g_serviceManager.AddService(L"wuauserv", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
        g_serviceManager.AddService(L"BITS", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_START);
        */

        // Check if services are suspended (shouldn't be at startup)
        SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scManager)
        {
            auto CheckAndRecover = [&](const wchar_t* name) {
                SC_HANDLE hSvc = OpenServiceW(scManager, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START);
                if (hSvc)
                {
                    // 1. Check if DISABLED first
            DWORD bytesNeeded = 0;
            // Fix C6031: Check return value (expect failure with buffer size)
            if (!QueryServiceConfigW(hSvc, nullptr, 0, &bytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(bytesNeeded);
                        LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
                        if (QueryServiceConfigW(hSvc, config, bytesNeeded, &bytesNeeded)) {
                            if (config->dwStartType == SERVICE_DISABLED) {
                                CloseServiceHandle(hSvc);
                                return; // Ignore disabled services
                            }
                        }
                    }

                    // 2. Check Status and Recover
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hSvc, &status))
                    {
                        if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
                        {
                            Log(std::string("[STARTUP] WARNING: ") + WideToUtf8(name) + " was stopped/paused - attempting recovery");
                            StartServiceW(hSvc, 0, nullptr);
                        }
                    }
                    CloseServiceHandle(hSvc);
                }
            };

            CheckAndRecover(L"wuauserv");
            CheckAndRecover(L"BITS");
            
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
    
    // Helper to pin thread to Efficiency cores (ARM64/Hybrid safe)
    auto PinBackgroundThread = [](std::thread& t) {
        if (!g_eCoreSets.empty()) {
            // Pin to first two Efficiency cores
            DWORD_PTR mask = 0;
            if (g_eCoreSets.size() >= 1) mask |= (1ULL << g_eCoreSets[0]);
            if (g_eCoreSets.size() >= 2) mask |= (1ULL << g_eCoreSets[1]);
            SetThreadAffinityMask(t.native_handle(), mask);
        }
        else if (g_physicalCoreCount >= 4) {
            // Legacy Fallback: Use last 2 physical cores
            DWORD_PTR affinityMask = (1ULL << (g_physicalCoreCount - 1)) | (1ULL << (g_physicalCoreCount - 2));
            SetThreadAffinityMask(t.native_handle(), affinityMask);
        }
        // Always lower priority to prevent interference
        SetThreadPriority(t.native_handle(), THREAD_PRIORITY_LOWEST);
    };
    
    std::thread configThread(IocpConfigWatcher);
    PinBackgroundThread(configThread);

    // Initialize unified background worker
    g_backgroundWorker = std::thread(BackgroundWorkerThread);
    PinBackgroundThread(g_backgroundWorker);
    Sleep(100); // [POLISH] Stagger start
    
    std::thread etwThread;
    if (g_caps.canUseEtw)
    {
        etwThread = std::thread(EtwThread);
        PinBackgroundThread(etwThread);
        Sleep(100); // [POLISH] Stagger start
    }
    
    std::thread watchdogThread(AntiInterferenceWatchdog);
    PinBackgroundThread(watchdogThread);
    Sleep(100); // [POLISH] Stagger start
    
    // Start Memory Optimizer in background thread
    std::thread memOptThread([]() {
        g_memoryOptimizer.RunThread();
    });
    PinBackgroundThread(memOptThread);
    memOptThread.detach(); // Allow it to run independently until app exit
	
    // FIX: Check return value (C6031)
    HRESULT hrInit = CoInitialize(nullptr);
    if (FAILED(hrInit)) {
        Log("[INIT] CoInitialize failed: " + std::to_string(hrInit));
    }

    // Network Intelligence
    g_networkMonitor.Initialize();
    
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
    wc.hInstance = g_hInst; // FIX: Use global instance handle
    RegisterClassW(&wc);
    
	// Parent must be nullptr (Top-level) for Tray Icon to receive events reliably
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"PriorityManagerTray", 0, 0, 0, 0, 0, 
                              nullptr, nullptr, g_hInst, nullptr); // FIX: Use global instance handle
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
                // Signal user activity to Smart Shell Booster
                g_explorerBooster.OnUserActivity();
                
                // Input Responsiveness Guard
                // Monitor latency and boost foreground threads
                g_inputGuardian.OnInput(msg.time);
                
                DefWindowProc(msg.hwnd, msg.message, msg.wParam, msg.lParam);
            }
            else if (msg.message == WM_POWERBROADCAST)
            {
                if (msg.wParam == PBT_APMQUERYSUSPEND || msg.wParam == PBT_APMSUSPEND)
                {
                    Log("System suspending - pausing operations to prevent memory corruption");
                    g_isSuspended.store(true);

                    // Switch to Power Saver when about to sleep
                    if (g_pSleepScheme == nullptr) {
                        if (PowerGetActiveScheme(NULL, &g_pSleepScheme) == ERROR_SUCCESS) {
                            if (PowerSetActiveScheme(NULL, &GUID_MAX_POWER_SAVINGS) == ERROR_SUCCESS) {
                                Log("[POWER] Switched to Efficiency power plan for sleep.");
                            } else {
                                LocalFree(g_pSleepScheme);
                                g_pSleepScheme = nullptr;
                            }
                        }
                    }
                }
                else if (msg.wParam == PBT_APMRESUMEAUTOMATIC || msg.wParam == PBT_APMRESUMESUSPEND)
                {
                    Log("System resumed - waiting 5s for kernel stability");
                    
                    // Restore Original Power Plan on wake
                    if (g_pSleepScheme != nullptr) {
                        if (PowerSetActiveScheme(NULL, g_pSleepScheme) == ERROR_SUCCESS) {
                            Log("[POWER] Restored original power plan.");
                        }
                        LocalFree(g_pSleepScheme);
                        g_pSleepScheme = nullptr;
                    }

                    // Fix: Move blocking wait to background thread to prevent UI freeze
                    std::thread([]() {
                        Sleep(5000); 
                        g_isSuspended.store(false);
                    }).detach();
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
            // [PERF FIX] Offload to persistent worker thread
            {
                std::lock_guard<std::mutex> lock(g_backgroundQueueMtx);
                g_backgroundTasks.push_back([]() {
                    Sleep(250);
                    // [CACHE] Atomic destruction on Config Reload
                    SessionSmartCache* oldCache = g_sessionCache.exchange(nullptr, std::memory_order_acquire);
                    if (oldCache) delete oldCache;
                    Sleep(250);
                    LoadConfig();
                });
            }
            g_backgroundCv.notify_one();
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        // Wait for messages with timeout - efficient polling that doesn't spin CPU
        // Use MsgWaitForMultipleObjects to stay responsive to inputs/shutdown while waiting
        DWORD waitResult = MsgWaitForMultipleObjects(1, &g_hShutdownEvent, FALSE, 100, QS_ALLINPUT);

        // [SAFETY] Fix C4189 & Prevent CPU spin if API fails
        if (waitResult == WAIT_FAILED) {
            Sleep(100); 
            continue;
        }

        // [OPTIMIZATION] If shutdown event signaled, skip tick logic to exit faster
        if (waitResult == WAIT_OBJECT_0) {
            continue;
        }
        
        // [FIX] MOVED OUTSIDE: Check tick timers regardless of input state
        // This ensures scanning happens even if the user is moving the mouse
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
                // FIX: Offload to persistent worker thread to protect Keyboard Hook
                {
                    std::lock_guard<std::mutex> lock(g_backgroundQueueMtx);
                    g_backgroundTasks.push_back([]{
						// Moved ExplorerBooster to background thread to prevent blocking the Keyboard Hook
						g_explorerBooster.OnTick();
						g_perfGuardian.OnPerformanceTick();
                    });
                }
                g_backgroundCv.notify_one();
                
                // Run Service Watcher
                ServiceWatcher::OnTick();
                
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
    UnregisterClassW(wc.lpszClassName, g_hInst); // FIX: Use global instance handle
    
    CoUninitialize();
    
	g_running = false;
    g_networkMonitor.Stop(); // Stop Monitor
    g_explorerBooster.Shutdown();
    g_inputGuardian.Shutdown();
    g_memoryOptimizer.Shutdown();
	
    // Signal threads to wake up/stop
    if (g_hShutdownEvent) SetEvent(g_hShutdownEvent); // Wakes Watchdog immediately
    StopEtwSession(); // Unblocks EtwThread (ProcessTrace returns)
    PostShutdown(); // Wakes IocpConfigWatcher
    
    // Stop background worker
    g_backgroundRunning = false;
    g_backgroundCv.notify_all();
    if (g_backgroundWorker.joinable()) g_backgroundWorker.join();

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
    
    // Safety cleanup for Power Scheme
    if (g_pSleepScheme != nullptr) {
        PowerSetActiveScheme(NULL, g_pSleepScheme);
        LocalFree(g_pSleepScheme);
        g_pSleepScheme = nullptr;
    }

    Log("=== Priority Manager Stopped ===");
    
    // Flush logs to disk before exit
    ShutdownLogger();

    return 0;
}
