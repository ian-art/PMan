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
#include "gui_manager.h"
#include "dark_mode.h"
#include "sram_engine.h"
#include "editor_manager.h"
#include "lifecycle.h"
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
#include <dwmapi.h>   // Required for DWM Dark Mode
#include <uxtheme.h>  // Required for Theme definitions
#include <array>

#pragma comment(lib, "PowrProf.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib") // For BITS monitoring
#pragma comment(lib, "Gdi32.lib") // Required for CreateFontW/DeleteObject
#pragma comment(lib, "Comctl32.lib") // Required for TaskDialog
#pragma comment(lib, "Dwmapi.lib") // DWM
#pragma comment(lib, "Uxtheme.lib") // UxTheme

// Force Linker to embed Manifest for Visual Styles (Required for TaskDialog)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// GLOBAL VARIABLE
HINSTANCE g_hInst = nullptr;
static NOTIFYICONDATAW g_nid = {}; // Defined early for visibility
static UINT g_wmTaskbarCreated = 0;

// --- Tray Animation Globals ---
#define TRAY_TIMER_ID 1
#define IDI_TRAY_FRAME_1 201
#define IDI_TRAY_FRAME_2 202
#define IDI_TRAY_FRAME_3 203
#define IDI_TRAY_FRAME_4 204
#define IDI_TRAY_FRAME_5 205
#define IDI_TRAY_FRAME_6 206
#define IDI_TRAY_FRAME_7 207
#define IDI_TRAY_FRAME_8 208

// --- Tray Animation Globals ---
#define IDI_TRAY_ORANGE_FRAME_1 209
#define IDI_TRAY_ORANGE_FRAME_2 210
#define IDI_TRAY_ORANGE_FRAME_3 211
#define IDI_TRAY_ORANGE_FRAME_4 212
#define IDI_TRAY_ORANGE_FRAME_5 213
#define IDI_TRAY_ORANGE_FRAME_6 214
#define IDI_TRAY_ORANGE_FRAME_7 215
#define IDI_TRAY_ORANGE_FRAME_8 216

static std::vector<HICON> g_framesNormal;
static std::vector<HICON> g_framesPaused;
static std::vector<HICON> g_framesCustom; // Custom loaded frames
static std::vector<HICON> g_framesCustomPaused; // Custom PAUSED frames
static std::vector<HICON>* g_activeFrames = nullptr; // Pointer to the currently active set
// g_currentThemeName replaced by g_iconTheme (globals.h)
static size_t g_currentFrame = 0;
// -----------------------------
HWND g_hLogWindow = nullptr; // Handle for Live Log Window
static std::atomic<bool> g_isCheckingUpdate{false};
static GUID* g_pSleepScheme = nullptr;
static HANDLE g_hGuardProcess = nullptr; // Handle to the watchdog process
static uint64_t g_resumeStabilizationTime = 0; // Replaces detached sleep thread;

// Removed LaunchProcessAsync (Dead Code / Unsafe Detach)
// All process launches now use synchronous CreateProcessW or the unified background worker.

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

// --- Responsiveness Manager (Hung App Recovery) ---
class ResponsivenessManager {
    struct HungState {
        DWORD pid = 0;
        HWND hwnd = nullptr;
        uint64_t hangStartTime = 0;
        bool boosted = false;
        bool prompted = false;
        DWORD originalPriority = NORMAL_PRIORITY_CLASS;
        int originalThreadPriority = THREAD_PRIORITY_NORMAL;
    } m_state;

    std::mutex m_mtx;

public:
    void Update() {
        std::lock_guard<std::mutex> lock(m_mtx);
        
        // MASTER TOGGLE: Check configuration
        if (!g_responsivenessRecoveryEnabled.load()) {
            if (m_state.pid != 0) {
                if (m_state.boosted) Revert();
                Reset();
            }
            return;
        }

        // GLOBAL CONSTRAINT: Disabled if Game Boost active
        if (g_perfGuardian.HasActiveSessions()) {
            if (m_state.boosted) Revert();
            Reset();
            return;
        }

        HWND hFg = GetForegroundWindow();
        if (!hFg) {
            // Focus lost or desktop, ensure we don't leave a boost hanging
            if (m_state.boosted) Revert();
            return;
        }

        // Detection
        // Signal 1: IsHungAppWindow (OS heuristic: no msg processing for 5s)
        bool isHung = IsWindowHung(hFg);

        if (isHung) {
            DWORD pid = 0;
            DWORD tid = GetWindowThreadProcessId(hFg, &pid);
            if (pid == 0) return;

            // SAFETY: Exclude Critical System Processes
            UniqueHandle hProcCheck(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (hProcCheck) {
                wchar_t path[MAX_PATH];
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcCheck.get(), 0, path, &sz)) {
                    std::wstring name = ExeFromPath(path);
                    // Critical exclusion list + PMan itself
                    if (IsSystemCriticalProcess(name) || name == L"pman.exe") return;
                }
            }

            uint64_t now = GetTickCount64();

            if (m_state.pid != pid) {
                // New hang detected
                Reset();
                m_state.pid = pid;
                m_state.hwnd = hFg;
                m_state.hangStartTime = now;
                // Log("[RESPONSIVE] Potential hang detected: PID " + std::to_string(pid));
            } else {
                // Persistent hang
                uint64_t duration = now - m_state.hangStartTime;

                // Soft Recovery Boost (> 2 seconds of hang)
                if (duration > 2000 && !m_state.boosted) {
                    ApplySoftBoost(pid, tid);
                }

                // User-Controlled Recovery (> 15 seconds)
                if (duration > 15000 && !m_state.prompted && m_state.boosted) {
                    // One-time prompt per hang instance
                    m_state.prompted = true; 
                    
                    // Check user preference for prompts
                    if (!g_recoveryPromptEnabled.load()) return;

                    // Dispatch to background worker to avoid blocking the main loop
                    std::thread([pid, name = GetProcessName(pid)]() {
                        std::wstring wName = name.empty() ? L"Application" : name;
                        std::wstring msg = wName + L" is not responding.\n\nPMAN can attempt to restart it, or you can wait.";
                        
                        int result = MessageBoxW(nullptr, msg.c_str(), L"Responsiveness Recovery", MB_ABORTRETRYIGNORE | MB_ICONWARNING | MB_TOPMOST);
                        
                        if (result == IDABORT) {
                            // User chose to kill/restart
                            UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
                            if (hProc) {
                                TerminateProcess(hProc.get(), 1);
                                Log("[RESPONSIVE] User terminated hung process PID " + std::to_string(pid));
                            }
                        }
                    }).detach();
                }
            }
        } else {
            // Observation & Revert
            // Window is responsive. If we were tracking it, revert changes.
            if (m_state.pid != 0) {
                if (m_state.boosted) {
                    Revert();
                    Log("[RESPONSIVE] Application recovered. Boosts reverted for PID " + std::to_string(m_state.pid));
                }
                Reset();
            }
        }
    }

private:
    void ApplySoftBoost(DWORD pid, DWORD tid) {
        // Safe Intervention: HIGH_PRIORITY (Not Realtime) + Thread Boost
        Log("[RESPONSIVE] Applying soft recovery boost to PID " + std::to_string(pid));
        
        m_state.originalPriority = NORMAL_PRIORITY_CLASS; // Default assumption
        
        UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProc) {
            m_state.originalPriority = GetPriorityClass(hProc.get());
            // Hard Limit: Do not boost if already High or Realtime
            if (m_state.originalPriority < HIGH_PRIORITY_CLASS) {
                SetPriorityClass(hProc.get(), HIGH_PRIORITY_CLASS);
            }
            
            // Temporary Affinity Expansion (Allow all cores)
            DWORD_PTR processAffinity, systemAffinity;
            if (GetProcessAffinityMask(hProc.get(), &processAffinity, &systemAffinity)) {
                if (processAffinity != systemAffinity) {
                    SetProcessAffinityMask(hProc.get(), systemAffinity);
                }
            }
        }

        // Boost UI Thread
        UniqueHandle hThread(OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid));
        if (hThread) {
            m_state.originalThreadPriority = GetThreadPriority(hThread.get());
            if (m_state.originalThreadPriority < THREAD_PRIORITY_HIGHEST) {
                SetThreadPriority(hThread.get(), THREAD_PRIORITY_HIGHEST);
            }
        }
        
        m_state.boosted = true;
    }

    void Revert() {
        if (m_state.pid == 0) return;

        UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION, FALSE, m_state.pid));
        if (hProc) {
            SetPriorityClass(hProc.get(), m_state.originalPriority);
        }

        if (m_state.hwnd) {
            DWORD tid = GetWindowThreadProcessId(m_state.hwnd, nullptr);
            UniqueHandle hThread(OpenThread(THREAD_SET_INFORMATION, FALSE, tid));
            if (hThread) {
                SetThreadPriority(hThread.get(), m_state.originalThreadPriority);
            }
        }
    }

    void Reset() {
        m_state = HungState{};
    }

    std::wstring GetProcessName(DWORD pid) {
        UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProc) {
            wchar_t path[MAX_PATH];
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
                return std::filesystem::path(path).filename().wstring();
            }
        }
        return L"";
    }
};

static ResponsivenessManager g_responsivenessManager;

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

        // Unified Dark Mode Application
        DarkMode::ApplyToWindow(g_hLogWindow);

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

            // [VISUAL] Apply Explorer Theme to Edit Control (Dark Scrollbars)
            SetWindowTheme(hEdit, L"Explorer", nullptr);

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

// [MOVED] Registry Guard implementation moved to restore.cpp

// Helper to update Tray Icon Tooltip with real-time status
static void UpdateTrayTooltip()
{
    std::wstring tip = L"Priority Manager";

    // 1. Protection Status
    if (g_userPaused.load()) {
        tip += L"\n\U0001F7E1 Status: PAUSED";
    } else {
        tip += L"\n\U0001F7E2 Status: Active";
    }

    // 2. Passive Mode (Idle Optimization Paused)
    if (g_pauseIdle.load()) {
        tip += L"\n\u2696 Passive: ON";
    }

    // 3. Awake Status
    if (g_keepAwake.load()) {
        tip += L"\n\u2600 Keep Awake: ON";
    }

    // 3. Current Mode (Optional - requires exposing g_lastMode in globals.h)
    if (g_sessionLocked.load()) {
         tip += L"\n\u1F3AE Mode: Gaming";
    }

    // SRAM Status
    LagState sramState = SramEngine::Get().GetStatus().state;
    if (sramState == LagState::SNAPPY) tip += L"\n\u26A1 System: Snappy";
    else if (sramState == LagState::SLIGHT_PRESSURE) tip += L"\n\u26A0 System: Pressure";
    else if (sramState == LagState::LAGGING) tip += L"\n\u26D4 System: Lagging";
    else if (sramState == LagState::CRITICAL_LAG) tip += L"\n\u2620 System: CRITICAL";

    // Safety: Truncate to 127 chars to prevent buffer overflow (szTip limit)
    if (tip.length() > 127) tip = tip.substr(0, 127);

    wcsncpy_s(g_nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// Forward declaration for main program logic
int RunMainProgram(int argc, wchar_t** argv);

// Notification Helper
static void ShowSramNotification(LagState state) {
    if (state <= LagState::SLIGHT_PRESSURE) return; // Don't annoy user for minor things

    // Rate Limit: Max 1 notification every 30 seconds
    static uint64_t lastNotify = 0;
    uint64_t now = GetTickCount64();
    if (now - lastNotify < 30000) return;
    lastNotify = now;

    std::wstring title = L"System Responsiveness Alert";
    std::wstring msg = L"";

    if (state == LagState::LAGGING) {
        msg = L"System is experiencing lag. Optimization scans have been deferred to restore responsiveness.";
        g_nid.dwInfoFlags = NIIF_WARNING;
    } else if (state == LagState::CRITICAL_LAG) {
        msg = L"CRITICAL LAG DETECTED. Entering 'Do No Harm' mode. All background operations stopped.";
        g_nid.dwInfoFlags = NIIF_ERROR;
    }

    wcsncpy_s(g_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(g_nid.szInfo, msg.c_str(), _TRUNCATE);
    g_nid.uFlags |= NIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    
    // Clear flag after sending to prevent stuck balloon
    g_nid.uFlags &= ~NIF_INFO;
}

// --- Custom Tray Animation Helpers ---
static void EnsureCustomFolderAndReadme() {
    try {
        std::filesystem::path baseDir = GetLogPath() / L"custom_icoanimation";
        
        // 1. Create directory if missing
        if (!std::filesystem::exists(baseDir)) {
            std::filesystem::create_directories(baseDir);
        }

        // 2. Create README if missing (ALWAYS check, even if dir existed)
        std::filesystem::path readmePath = baseDir / L"README.txt";
        if (!std::filesystem::exists(readmePath)) {
            std::ofstream readme(readmePath);
            if (readme.is_open()) {
                readme << "PMan Custom Tray Animations\n"
                       << "===========================\n\n"
                       << "How to install a theme:\n"
                       << "1. Create a folder with your theme name (e.g. 'Matrix') inside this folder.\n"
                       << "2. Add 8 icons for the ACTIVE animation named:\n"
                       << "   frame_01.ico, frame_02.ico ... frame_08.ico\n"
                       << "3. (Optional) Add 8 icons for the PAUSED animation named:\n"
                       << "   p_frame_01.ico, p_frame_02.ico ... p_frame_08.ico\n\n"
                       << "Note:\n"
                       << "- If paused icons (p_*) are missing, PMan will use the active icons for the paused state.\n";
                readme.close();
            }
        }
    } catch (...) {}
}

static std::vector<std::wstring> ScanAnimationThemes() {
    EnsureCustomFolderAndReadme(); 
    std::vector<std::wstring> themes;
    try {
        std::filesystem::path baseDir = GetLogPath() / L"custom_icoanimation";
        if (std::filesystem::exists(baseDir)) {
            for (const auto& entry : std::filesystem::directory_iterator(baseDir)) {
                if (entry.is_directory()) {
                    // Validate: Only list themes that have at least the first frame
                    if (std::filesystem::exists(entry.path() / L"frame_01.ico")) {
                        themes.push_back(entry.path().filename().wstring());
                    }
                }
            }
        }
    } catch (...) {}
    return themes;
}

static void SetCustomTheme(const std::wstring& themeName) {
    // Cleanup previous custom icons
    for (HICON h : g_framesCustom) DestroyIcon(h);
    g_framesCustom.clear();
    for (HICON h : g_framesCustomPaused) DestroyIcon(h);
    g_framesCustomPaused.clear();

    if (themeName == L"Default") {
        g_iconTheme = L"Default";
        g_activeFrames = g_userPaused.load() ? &g_framesPaused : &g_framesNormal;
    } else {
        std::filesystem::path themePath = GetLogPath() / L"custom_icoanimation" / themeName;
        
        // 1. Load Normal Frames
        for (int i = 1; i <= 8; ++i) {
            wchar_t filename[32];
            swprintf_s(filename, L"frame_%02d.ico", i);
            HICON hIcon = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
            if (hIcon) g_framesCustom.push_back(hIcon);
        }

        // 2. Load Paused Frames (p_*)
        bool foundPaused = false;
        for (int i = 1; i <= 8; ++i) {
            wchar_t filename[32];
            swprintf_s(filename, L"p_frame_%02d.ico", i);
            HICON hIcon = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
            if (hIcon) {
                g_framesCustomPaused.push_back(hIcon);
                foundPaused = true;
            }
        }

        // 3. Fallback: If no specific paused icons, reuse normal icons (reload to get distinct handles)
        if (!foundPaused || g_framesCustomPaused.empty()) {
            for (HICON h : g_framesCustomPaused) DestroyIcon(h); // Cleanup partials
            g_framesCustomPaused.clear();
            for (int i = 1; i <= 8; ++i) {
                wchar_t filename[32];
                swprintf_s(filename, L"frame_%02d.ico", i);
                HICON hIcon = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
                if (hIcon) g_framesCustomPaused.push_back(hIcon);
            }
        }

        if (!g_framesCustom.empty()) {
            g_iconTheme = themeName;
            g_activeFrames = g_userPaused.load() ? &g_framesCustomPaused : &g_framesCustom;
        } else {
            g_iconTheme = L"Default";
            g_activeFrames = g_userPaused.load() ? &g_framesPaused : &g_framesNormal;
        }
    }

    g_currentFrame = 0;
    if (g_activeFrames && !g_activeFrames->empty()) {
        g_nid.hIcon = (*g_activeFrames)[0];
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    }
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
        // Ensure custom folder structure exists immediately on startup
        EnsureCustomFolderAndReadme();

        // 1. Load Normal Frames
        for (int i = 0; i < 8; i++) {
            g_framesNormal.push_back(LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_TRAY_FRAME_1 + i)));
        }

        // 2. Load Paused (Orange) Frames
        for (int i = 0; i < 8; i++) {
            g_framesPaused.push_back(LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_TRAY_ORANGE_FRAME_1 + i)));
        }

        // 3. Set Initial State
        if (g_iconTheme != L"Default") {
            SetCustomTheme(g_iconTheme);
        } else {
            g_activeFrames = &g_framesNormal;
        }

        g_nid.cbSize = sizeof(NOTIFYICONDATAW);
        g_nid.hWnd = hwnd;
        g_nid.uID = ID_TRAY_APP_ICON;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WM_TRAYICON;
        
        // Initial Icon
        if (!g_activeFrames->empty()) {
            g_nid.hIcon = (*g_activeFrames)[0];
        } else {
            g_nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        }
        
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        UpdateTrayTooltip(); // Set initial text
        
        // Start Animation Timer (150ms)
        SetTimer(hwnd, TRAY_TIMER_ID, 150, nullptr);

        // [DARK MODE] Apply Centralized Dark Mode
        DarkMode::ApplyToWindow(hwnd);
        return 0;

    // [DARK MODE] Refresh Menu Themes if system theme changes
    case WM_TIMER:
        if (wParam == TRAY_TIMER_ID && g_activeFrames && !g_activeFrames->empty())
        {
            // Simple cyclic animation on the active set
            g_currentFrame = (g_currentFrame + 1) % g_activeFrames->size();
            g_nid.hIcon = (*g_activeFrames)[g_currentFrame];
            Shell_NotifyIconW(NIM_MODIFY, &g_nid);
        }
        return 0;

    case WM_THEMECHANGED:
    case WM_SETTINGCHANGE:
        DarkMode::RefreshTheme();      // Flushes the Windows menu theme cache
        DarkMode::ApplyToWindow(hwnd);
        if (g_hLogWindow) DarkMode::ApplyToWindow(g_hLogWindow); // Update log window if open
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            SetForegroundWindow(hwnd);
            
            // Ensure owner window state is current before menu creation
            DarkMode::ApplyToWindow(hwnd);
            
            // Detect best available editor via EditorManager
            std::wstring editorName = EditorManager::GetEditorName();

            HMENU hMenu = CreatePopupMenu();

            // Apply Dark Mode styles to the context menu
            DarkMode::ApplyToMenu(hMenu);
            
            bool paused = g_userPaused.load();

            // 1. Dashboards Submenu
            HMENU hDashMenu = CreatePopupMenu();
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_LIVE_LOG, L"Live Log Viewer");
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_OPEN_DIR, L"Open Log Folder");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDashMenu, L"Monitor & Logs");

            // --- Theme Selection Submenu ---
            HMENU hThemeMenu = CreatePopupMenu();
            AppendMenuW(hThemeMenu, MF_STRING | (g_iconTheme == L"Default" ? MF_CHECKED : 0), ID_TRAY_THEME_BASE, L"Default (Embedded)");
            
            std::vector<std::wstring> themes = ScanAnimationThemes();
            int themeId = ID_TRAY_THEME_BASE + 1;
            for (const auto& theme : themes) {
                bool isSelected = (g_iconTheme == theme);
                AppendMenuW(hThemeMenu, MF_STRING | (isSelected ? MF_CHECKED : 0), themeId++, theme.c_str());
            }
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hThemeMenu, L"Icon Theme");

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
			AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hControlMenu, MF_STRING, ID_TRAY_APPLY_TWEAKS, L"TuneUp System");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
			bool awake = g_keepAwake.load();
            AppendMenuW(hControlMenu, MF_STRING | (awake ? MF_CHECKED : 0), ID_TRAY_KEEP_AWAKE, L"Keep System Awake");
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
                cachedMode = Lifecycle::GetStartupMode(taskName); 
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
            TrackPopupMenuEx(
				hMenu,
				TPM_BOTTOMALIGN | TPM_RIGHTALIGN | TPM_NOANIMATION,
				pt.x,
				pt.y,
				hwnd,
				nullptr
			);
            
            DestroyMenu(hControlMenu);
            DestroyMenu(hConfigMenu);
            DestroyMenu(hDashMenu);
            DestroyMenu(hThemeMenu);
            DestroyMenu(hHelpMenu);
            DestroyMenu(hMenu);
        }
        return 0;

    case WM_COMMAND:
    {
        DWORD wmId = LOWORD(wParam);
        
        // --- Theme Handler ---
        if (wmId >= ID_TRAY_THEME_BASE && wmId < ID_TRAY_THEME_BASE + 100) {
            std::wstring newTheme = L"Default";
            if (wmId != ID_TRAY_THEME_BASE) {
                std::vector<std::wstring> themes = ScanAnimationThemes();
                int index = wmId - (ID_TRAY_THEME_BASE + 1);
                if (index >= 0 && index < themes.size()) {
                    newTheme = themes[index];
                }
            }
            SetCustomTheme(newTheme);
            SaveIconTheme(newTheme);
        }
        
        // --- New Handlers ---
        if (wmId == ID_TRAY_LIVE_LOG) {
            GuiManager::ShowLogWindow();
        }
        else if (wmId == ID_TRAY_OPEN_DIR) {
            ShellExecuteW(nullptr, L"open", GetLogPath().c_str(), nullptr, nullptr, SW_SHOW);
        }
		else if (wmId == ID_TRAY_EDIT_CONFIG) {
            EditorManager::OpenFile(CONFIG_FILENAME);
        }
		else if (wmId == ID_TRAY_EDIT_GAMES) {
            EditorManager::OpenConfigAtSection(L"[games]");
        }
        else if (wmId == ID_TRAY_EDIT_BROWSERS) {
            EditorManager::OpenConfigAtSection(L"[browsers]");
        }
        else if (wmId == ID_TRAY_EDIT_VIDEO_PLAYERS) {
            EditorManager::OpenConfigAtSection(L"[video_players]");
        }
		else if (wmId == ID_TRAY_EDIT_IGNORED) {
            EditorManager::OpenFile(IGNORED_PROCESSES_FILENAME);
        }
		else if (wmId == ID_TRAY_EDIT_LAUNCHERS) {
            EditorManager::OpenFile(CUSTOM_LAUNCHERS_FILENAME);
        }
		// --- End New Handlers ---

        else if (wmId == ID_TRAY_STARTUP_DISABLED) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            Lifecycle::UninstallTask(taskName);
        }
        else if (wmId == ID_TRAY_STARTUP_ACTIVE || wmId == ID_TRAY_STARTUP_PASSIVE) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            bool passive = (wmId == ID_TRAY_STARTUP_PASSIVE);
            Lifecycle::InstallTask(taskName, self, passive);
        }
        else if (wmId == ID_TRAY_EXIT) {
            DestroyWindow(hwnd);
        } 
        else if (wmId == ID_TRAY_ABOUT) {
            GuiManager::ShowAboutWindow();
        }
        else if (wmId == ID_TRAY_SUPPORT) {
            ShellExecuteW(nullptr, L"open", SUPPORT_URL, nullptr, nullptr, SW_SHOWNORMAL);
        }
        else if (wmId == ID_TRAY_HELP_USAGE) {
            GuiManager::ShowHelpWindow();
        }
        else if (wmId == ID_TRAY_UPDATE) {
            OpenUpdatePage();
        }
        else if (wmId == ID_TRAY_APPLY_TWEAKS) {
            // Open the new GUI Window instead of the old message box
            GuiManager::ShowTuneUpWindow();
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

            // --- ANIMATION STATE SWITCH ---
            // 1. Swap the pointer based on Theme
            if (p) { // Paused
                if (g_iconTheme == L"Default") g_activeFrames = &g_framesPaused;
                else g_activeFrames = &g_framesCustomPaused;
            } else { // Resumed
                if (g_iconTheme == L"Default") g_activeFrames = &g_framesNormal;
                else g_activeFrames = &g_framesCustom;
            }
            
            // 2. Reset index to start fresh immediately
            g_currentFrame = 0;
            
            // 3. Force immediate icon update (don't wait for timer)
            if (g_activeFrames && !g_activeFrames->empty()) {
                g_nid.hIcon = (*g_activeFrames)[0];
                Shell_NotifyIconW(NIM_MODIFY, &g_nid);
            }
            // -----------------------------

            UpdateTrayTooltip(); 
            Log(p ? "[USER] Protection PAUSED." : "[USER] Protection RESUMED.");
            if (!p) g_reloadNow.store(true);
        }
        else if (wmId == ID_TRAY_PAUSE_IDLE) {
            bool p = !g_pauseIdle.load();
            g_pauseIdle.store(p);

            UpdateTrayTooltip(); // Refresh tooltip immediately

            Log(p ? "[USER] Idle Optimization PAUSED (CPU Limiting Disabled)." : "[USER] Idle Optimization RESUMED.");

            // Immediate effect: If we just paused, force the Idle Manager to think we are active
            // This restores all parked cores instantly.
            if (p) {
                g_idleAffinityMgr.OnIdleStateChanged(false); 
            }
        }
        else if (wmId == ID_TRAY_KEEP_AWAKE) {
            bool k = !g_keepAwake.load();
            g_keepAwake.store(k);

            if (k) {
                // Prevent Sleep (System) and Screen Off (Display)
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
                Log("[USER] Keep Awake ENABLED (System Sleep & Display Off blocked).");
            } else {
                // Clear flags, allow OS to sleep normally
                SetThreadExecutionState(ES_CONTINUOUS);
                Log("[USER] Keep Awake DISABLED (System power settings restored).");
            }
            UpdateTrayTooltip(); // Refresh Tooltip
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
        // Cleanup Custom Icons
        for (HICON h : g_framesCustom) DestroyIcon(h);
        g_framesCustom.clear();
        for (HICON h : g_framesCustomPaused) DestroyIcon(h);
        g_framesCustomPaused.clear();

        KillTimer(hwnd, TRAY_TIMER_ID);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

int wmain(int argc, wchar_t* argv[])
{
	try {
	
    // [DARK MODE] Initialize Centralized Dark Mode Manager
	DarkMode::Initialize();
    
    // Initialize Telemetry-Safe Logger
    InitLogger();

    // Lifecycle Management
    std::vector<std::thread> lifecycleThreads;

	// 1. Initialize Global Instance Handle (Required for Tray Icon)
    g_hInst = GetModuleHandle(nullptr);

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
    if (argc >= 5 && (std::wstring(argv[1]) == L"--guard"))
    {
        DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        // Fixed: Removed redundant low/high split. Expecting direct value.
        DWORD val = std::wcstoul(argv[3], nullptr, 10); 
        std::wstring powerScheme = argv[4];
        
        RunRegistryGuard(pid, val, powerScheme);
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
        Lifecycle::TerminateExistingInstances();

		if (!Lifecycle::IsTaskInstalled(taskName))
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

        Lifecycle::UninstallTask(taskName);

        if (!silent)
        {
            MessageBoxW(nullptr, 
                L"Priority Manager has been successfully uninstalled.\nAny running instance has been stopped and the startup task removed.", 
                L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }

        if (g_hMutex) { CloseHandle(g_hMutex); g_hMutex = nullptr; }
        return 0;
    }

	bool taskExists = Lifecycle::IsTaskInstalled(taskName);

    if (!taskExists)
    {
        // Install in Active mode (false for passive), with /S implied by Lifecycle::InstallTask default logic
        if (Lifecycle::InstallTask(taskName, self, false)) 
        {
             // Wait briefly to ensure task registration propagates
             Sleep(500);
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

    // Initialize SRAM (System Responsiveness Awareness Module)
    // Must be initialized before subsystems that depend on LagState
    SramEngine::Get().Initialize();

    DetectOSCapabilities();
    // Managed thread lifetime (removed detach)
    std::thread restoreThread([]() {
        EnsureStartupRestorePoint();
    });
    lifecycleThreads.push_back(std::move(restoreThread));
    
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
    // Store for clean shutdown
    lifecycleThreads.push_back(std::move(memOptThread));
	
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
            // Capture handle for lifecycle management
            g_hGuardProcess = LaunchRegistryGuard(currentSetting);
            
            if (!g_hGuardProcess || g_hGuardProcess == INVALID_HANDLE_VALUE) {
                Log("[CRITICAL] Failed to launch Registry Guard. Crash protection disabled.");
                g_hGuardProcess = nullptr;
            }
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

					// State-based delay instead of detached thread
					g_resumeStabilizationTime = GetTickCount64() + 5000;
					g_isSuspended.store(true); // Keep suspended until stabilization
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
                    g_sessionCache.store(nullptr, std::memory_order_release);
                    Sleep(250);
                    LoadConfig();
                });
            }
            g_backgroundCv.notify_one();
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        // Handle Resume Stabilization (Non-blocking)
        if (g_resumeStabilizationTime > 0) {
             if (GetTickCount64() >= g_resumeStabilizationTime) {
                 g_isSuspended.store(false);
                 g_resumeStabilizationTime = 0;
                 Log("System stabilized - resuming operations");
             }
        }

        // GUI Rendering Integration
        if (GuiManager::IsWindowOpen()) {
            GuiManager::RenderFrame();
        }

        // Wait for messages with timeout - efficient polling that doesn't spin CPU
        // Use MsgWaitForMultipleObjects to stay responsive to inputs/shutdown while waiting
        // Reduced timeout to 16ms (~60 FPS) only when GUI is open to ensure smooth rendering
        DWORD waitTimeout = GuiManager::IsWindowOpen() ? 16 : 100;
        DWORD waitResult = MsgWaitForMultipleObjects(1, &g_hShutdownEvent, FALSE, waitTimeout, QS_ALLINPUT);

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

                // Run Responsiveness Manager (Hung App Recovery)
                // Checks foreground window state and applies safe boosts if hung
                g_responsivenessManager.Update();

                // SRAM UI Updates
                static LagState lastKnownState = LagState::SNAPPY;
                LagState currentState = SramEngine::Get().GetStatus().state;
                
                if (currentState != lastKnownState) {
                    UpdateTrayTooltip(); // Refresh tooltip text
                    ShowSramNotification(currentState); // Show balloon if critical
                    lastKnownState = currentState;
                }
                
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

    GuiManager::Shutdown(); // Cleanup DX11/ImGui resources

	UnregisterPowerNotifications();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, g_hInst); // FIX: Use global instance handle
    
    CoUninitialize();
    
	g_running = false;
    g_networkMonitor.Stop(); // Stop Monitor
    g_explorerBooster.Shutdown();
    g_inputGuardian.Shutdown();
    g_memoryOptimizer.Shutdown();
    SramEngine::Get().Shutdown();
	
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
    
    // Join managed lifecycle threads
    for (auto& t : lifecycleThreads) {
        if (t.joinable()) t.join();
    }
    
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

    // Terminate Guard Process on graceful shutdown to prevent false positives
    if (g_hGuardProcess) {
        TerminateProcess(g_hGuardProcess, 0);
        CloseHandle(g_hGuardProcess);
        g_hGuardProcess = nullptr;
        Log("[GUARD] Watchdog process terminated gracefully.");
    }

    Log("=== Priority Manager Stopped ===");
    
    // Flush logs to disk before exit
    ShutdownLogger();

    return 0;

    } catch (const std::exception& e) {
        // Top-level crash boundary
        std::string msg = "[CRITICAL] Unhandled exception in main: ";
        msg += e.what();
        
        // Try logging to disk
        try {
            Log(msg);
            ShutdownLogger(); // Force flush
        } catch (...) {
            // Ignore secondary failures during crash handling
        }

        // Deterministic failure - visible to OS/User
        MessageBoxA(nullptr, msg.c_str(), "Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;

    } catch (...) {
        // Catch non-standard exceptions
        try {
            Log("[CRITICAL] Unknown non-standard exception caught in main.");
            ShutdownLogger();
        } catch (...) {
            // Ignore secondary failures
        }

        MessageBoxW(nullptr, L"Unknown fatal error occurred.", L"Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;
    }
}
