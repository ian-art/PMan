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

#include "tray_animator.h"
#include "utils.h"
#include "logger.h"
#include "constants.h"
#include "globals.h"          // g_userPaused, g_pauseIdle, g_keepAwake, g_isSuspended,
                               // g_reloadNow, g_iconTheme, g_idleAffinityMgr, g_hInst,
                               // g_isCheckingUpdate, g_resumeStabilizationTime
#include "context.h"          // PManContext::Get()
#include "provenance_ledger.h"// ProvenanceLedger::Record, DecisionJustification
#include "sandbox_executor.h" // SandboxResult (member of DecisionJustification)
#include "authority_budget.h" // AuthorityBudget::IsExhausted (complete type required)
#include "dark_mode.h"        // DarkMode::ApplyToWindow, ApplyToMenu, IsEnabled, RefreshTheme
#include "log_viewer.h"       // LogViewer::ApplyTheme
#include "gui_manager.h"      // GuiManager::ShowConfigWindow, ShowLogWindow, etc.
#include "lifecycle.h"        // Lifecycle::GetStartupMode, InstallTask, UninstallTask
#include "sram_engine.h"      // SramEngine, LagState
#include "config.h"           // SaveIconTheme
#include <shellapi.h>
#include <filesystem>
#include <fstream>
#include <chrono>

// IconToBitmapPARGB32 and OpenUpdatePage declared in utils.h (included above).
// SaveIconTheme declared in config.h (included above).
// GuiManager::OpenPolicyTab declared in gui_manager.h (included above).

// Memory Cleaner External Definition
extern ULONGLONG PerformClean(bool aggressive, bool dryRun);

// ---------------------------------------------------------------------------
// Auto Memory Monitor — TrayAnimator member implementations
// ---------------------------------------------------------------------------
bool TrayAnimator::IsMemMonitorActive(DWORD threshold) const {
    return m_memMonitorRunning.load() && m_memMonitorThreshold.load() == threshold;
}

void TrayAnimator::StartMemMonitor(DWORD threshold) {
    // Stop any existing monitor before starting the new one
    m_memMonitorRunning.store(false);
    if (m_memMonitorThread.joinable()) m_memMonitorThread.join();

    m_memMonitorThreshold.store(threshold);
    m_memMonitorRunning.store(true);

    m_memMonitorThread = std::thread([this, threshold]() {
        Log("[MEM] Auto-monitor STARTED at " + std::to_string(threshold) + "% threshold.");
        ShowNotification(L"Memory Monitor",
            threshold == 80 ? L"Auto-clean active: triggers at 80% usage."
                            : L"Auto-clean active: triggers at 90% usage.",
            NIIF_INFO);

        constexpr DWORD POLL_MS     = 10000; // check every 10 seconds
        constexpr DWORD COOLDOWN_MS = 60000; // minimum 60s between auto-cleans

        uint64_t lastCleanTime = 0;

        while (m_memMonitorRunning.load() && g_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_MS));

            if (!m_memMonitorRunning.load() || !g_running.load()) break;

            // [SAFETY GATE] Halt autonomous trimming to prevent I/O storms and stuttering 
            // during critical system states, sleep transitions, or gaming sessions.
            if (g_sessionLocked.load() || g_isSuspended.load() || 
                SramEngine::Get().GetStatus().state >= LagState::LAGGING) {
                continue;
            }

            MEMORYSTATUSEX ms = { sizeof(ms) };
            if (!GlobalMemoryStatusEx(&ms)) continue;

            if (ms.dwMemoryLoad >= threshold) {
                uint64_t now = GetTickCount64();
                if (now - lastCleanTime < COOLDOWN_MS) continue; // still in cooldown

                lastCleanTime = now;
                Log("[MEM] Auto-monitor: usage " + std::to_string(ms.dwMemoryLoad) +
                    "% >= " + std::to_string(threshold) + "%. Running auto-clean.");

                ULONGLONG freed = PerformClean(false, false);
                double freedMB = static_cast<double>(freed) / (1024.0 * 1024.0);
                wchar_t msg[128];
                swprintf_s(msg, 128, L"Auto-clean triggered at %lu%%.\nFreed: %.2f MB",
                    ms.dwMemoryLoad, freedMB);
                ShowNotification(L"Memory Monitor", msg, NIIF_INFO);
                Log("[MEM] Auto-clean freed " + std::to_string(freedMB) + " MB.");
            }
        }
        Log("[MEM] Auto-monitor STOPPED.");
    });
}

void TrayAnimator::StopMemMonitor() {
    m_memMonitorRunning.store(false);
    m_memMonitorThreshold.store(0);
    if (m_memMonitorThread.joinable()) m_memMonitorThread.join();
    Log("[MEM] Auto-monitor STOPPED by user.");
    ShowNotification(L"Memory Monitor", L"Auto-monitor disabled.", NIIF_INFO);
}

// Resource IDs (Copied from main.cpp to isolate dependency)
#define IDI_TRAY_FRAME_1 201
#define IDI_TRAY_ORANGE_FRAME_1 209

TrayAnimator& TrayAnimator::Get() {
    static TrayAnimator instance;
    return instance;
}

TrayAnimator::TrayAnimator() = default;

TrayAnimator::~TrayAnimator() {
    Shutdown();
}

void TrayAnimator::Shutdown() {
    if (!m_initialized) return;

    // Stop auto memory monitor — must join before destroying resources
    m_memMonitorRunning.store(false);
    if (m_memMonitorThread.joinable()) m_memMonitorThread.join();

    KillTimer(m_hwnd, TIMER_ID);
    Shell_NotifyIconW(NIM_DELETE, &m_nid);
    
    FreeIcons(m_framesNormal);
    FreeIcons(m_framesPaused);
    FreeIcons(m_framesCustom);
    FreeIcons(m_framesCustomPaused);
    
    m_initialized = false;
}

void TrayAnimator::FreeIcons(std::vector<HICON>& icons) {
    for (HICON h : icons) {
        if (h) DestroyIcon(h);
    }
    icons.clear();
}

void TrayAnimator::Initialize(HINSTANCE hInstance, HWND hwnd) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_initialized) return;

    m_hInst = hInstance;
    m_hwnd = hwnd;

    // Load Stock Resources
    LoadResources();
    
    // Set Initial Active Set
    m_activeFrames = &m_framesNormal;
    
    // Initialize NotifyIconData
    m_nid.cbSize = sizeof(NOTIFYICONDATAW);
    m_nid.hWnd = m_hwnd;
    // Use the ID defined in main.cpp/constants.h if available, otherwise internal unique ID
    // Note: main.cpp uses ID_TRAY_APP_ICON. We assume it matches 1 or we override it here.
    // For safety, we use the value usually defined in constants.h or defaults.
    #ifdef ID_TRAY_APP_ICON
    m_nid.uID = ID_TRAY_APP_ICON;
    #else
    m_nid.uID = ICON_UID; 
    #endif
    
    m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    m_nid.uCallbackMessage = WM_TRAYICON; // Defined in constants.h
    
    if (!m_activeFrames->empty()) {
        m_nid.hIcon = (*m_activeFrames)[0];
    } else {
        m_nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    }
    
    if (!Shell_NotifyIconW(NIM_ADD, &m_nid)) {
        Log("[TRAY] Warning: Failed to add tray icon during init.");
    }
    
    // Start Animation Timer (150ms)
    SetTimer(m_hwnd, TIMER_ID, 150, nullptr);
    
    EnsureCustomFolder();
    m_initialized = true;
    m_lastTick.store(GetTickCount64());
    Log("[TRAY] Animator initialized.");
}

void TrayAnimator::LoadResources() {
    // Normal Frames
    for (int i = 0; i < 8; i++) {
        HICON h = LoadIcon(m_hInst, MAKEINTRESOURCE(IDI_TRAY_FRAME_1 + i));
        if (h) m_framesNormal.push_back(h);
    }

    // Paused Frames
    for (int i = 0; i < 8; i++) {
        HICON h = LoadIcon(m_hInst, MAKEINTRESOURCE(IDI_TRAY_ORANGE_FRAME_1 + i));
        if (h) m_framesPaused.push_back(h);
    }
}

void TrayAnimator::OnTimer(WPARAM timerId) {
    if (!m_initialized || timerId != TIMER_ID) return;

    m_lastTick.store(GetTickCount64());
    std::lock_guard<std::mutex> lock(m_mtx);
    UpdateIcon();
}

void TrayAnimator::UpdateIcon() {
    if (!m_activeFrames || m_activeFrames->empty()) return;

    m_currentFrame = (m_currentFrame + 1) % m_activeFrames->size();
    m_nid.hIcon = (*m_activeFrames)[m_currentFrame];
    
    if (!Shell_NotifyIconW(NIM_MODIFY, &m_nid)) {
        // [FIX] Self-Healing: If modify fails (e.g. icon lost), try adding it back
        static int retryCount = 0;
        if (retryCount++ < 3) {
            Shell_NotifyIconW(NIM_ADD, &m_nid);
        }
    }
}

void TrayAnimator::OnTaskbarRestart() {
    std::lock_guard<std::mutex> lock(m_mtx);
    Shell_NotifyIconW(NIM_ADD, &m_nid);
    Log("[TRAY] Restored icon after Taskbar restart.");
}

void TrayAnimator::SetPaused(bool paused) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_isPaused == paused) return;
    
    m_isPaused = paused;
    
    // Switch Sets
    if (m_currentTheme == L"Default") {
        m_activeFrames = m_isPaused ? &m_framesPaused : &m_framesNormal;
    } else {
        m_activeFrames = m_isPaused ? &m_framesCustomPaused : &m_framesCustom;
    }
    
    m_currentFrame = 0;
    
    // Immediate Update
    if (m_activeFrames && !m_activeFrames->empty()) {
        m_nid.hIcon = (*m_activeFrames)[0];
        Shell_NotifyIconW(NIM_MODIFY, &m_nid);
    }
}

void TrayAnimator::UpdateTooltip(const std::wstring& text) {
    std::lock_guard<std::mutex> lock(m_mtx);
    wcsncpy_s(m_nid.szTip, text.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
}

void TrayAnimator::ShowNotification(const std::wstring& title, const std::wstring& msg, DWORD flags) {
    std::lock_guard<std::mutex> lock(m_mtx);
    wcsncpy_s(m_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(m_nid.szInfo, msg.c_str(), _TRUNCATE);
    m_nid.uFlags |= NIF_INFO;
    m_nid.dwInfoFlags = flags;
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
    m_nid.uFlags &= ~NIF_INFO; // Clear flag
}

void TrayAnimator::EnsureCustomFolder() {
    try {
        std::filesystem::path baseDir = GetLogPath() / L"custom_icoanimation";
        if (!std::filesystem::exists(baseDir)) {
            std::filesystem::create_directories(baseDir);
        }
        std::filesystem::path readmePath = baseDir / L"README.txt";
        if (!std::filesystem::exists(readmePath)) {
            std::ofstream readme(readmePath);
            if (readme.is_open()) {
                readme << "PMan Custom Tray Animations\n"
                       << "1. Create folder with theme name.\n"
                       << "2. Add frame_01.ico ... frame_08.ico\n"
                       << "3. Optional: p_frame_01.ico ... for paused state.\n";
            }
        }
    } catch (...) {}
}

std::vector<std::wstring> TrayAnimator::ScanThemes() {
    std::vector<std::wstring> themes;
    try {
        std::filesystem::path baseDir = GetLogPath() / L"custom_icoanimation";
        if (std::filesystem::exists(baseDir)) {
            for (const auto& entry : std::filesystem::directory_iterator(baseDir)) {
                if (entry.is_directory() && std::filesystem::exists(entry.path() / L"frame_01.ico")) {
                    themes.push_back(entry.path().filename().wstring());
                }
            }
        }
    } catch (...) {}
    return themes;
}

void TrayAnimator::LoadCustomFrames(const std::wstring& themeName) {
    // This function is internal, caller holds lock? 
    // Actually SetTheme calls this.
    
    FreeIcons(m_framesCustom);
    FreeIcons(m_framesCustomPaused);

    std::filesystem::path themePath = GetLogPath() / L"custom_icoanimation" / themeName;
    
    // Load Normal
    for (int i = 1; i <= 8; ++i) {
        wchar_t filename[32];
        swprintf_s(filename, L"frame_%02d.ico", i);
        HICON h = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
        if (h) m_framesCustom.push_back(h);
    }
    
    // Load Paused
    bool foundPaused = false;
    for (int i = 1; i <= 8; ++i) {
        wchar_t filename[32];
        swprintf_s(filename, L"p_frame_%02d.ico", i);
        HICON h = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
        if (h) {
            m_framesCustomPaused.push_back(h);
            foundPaused = true;
        }
    }
    
    // Fallback
    if (!foundPaused) {
        for (int i = 1; i <= 8; ++i) {
            wchar_t filename[32];
            swprintf_s(filename, L"frame_%02d.ico", i);
            HICON h = (HICON)LoadImageW(nullptr, (themePath / filename).c_str(), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_DEFAULTSIZE);
            if (h) m_framesCustomPaused.push_back(h);
        }
    }
}

LRESULT TrayManager::HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    // -----------------------------------------------------------------------
    case WM_CREATE:
        // Initialize Tray Animation Subsystem
        TrayAnimator::Get().Initialize(g_hInst, hwnd);

        // Restore saved state
        if (g_iconTheme != L"Default") {
            TrayAnimator::Get().SetTheme(g_iconTheme);
        }
        TrayAnimator::Get().SetPaused(g_userPaused.load());

        UpdateTrayTooltip(); // Set initial text

        // [DARK MODE] Apply Centralized Dark Mode
        DarkMode::ApplyToWindow(hwnd);
        // Keep heartbeat alive during modal loops (e.g., TrackPopupMenuEx, Apply Tweaks)
        SetTimer(hwnd, 9999, 1000, nullptr);
        return 0;

    // -----------------------------------------------------------------------
    // [DARK MODE] Refresh Menu Themes if system theme changes
    case WM_TIMER:
        if (wParam == 9999) {
            if (auto* hb = PManContext::Get().runtime.pHeartbeat) {
                hb->counter.fetch_add(1, std::memory_order_relaxed);
                hb->last_tick = GetTickCount64();
            }
            return 0;
        }
        TrayAnimator::Get().OnTimer(wParam);
        return 0;

    // -----------------------------------------------------------------------
    case WM_THEMECHANGED:
    case WM_SETTINGCHANGE:
        DarkMode::RefreshTheme();      // Flushes the Windows menu theme cache
        DarkMode::ApplyToWindow(hwnd);
        LogViewer::ApplyTheme();       // Update log window if open
        return 0;

    // -----------------------------------------------------------------------
    case WM_TRAYICON:
        // Handle Balloon Click (NIN_BALLOONUSERCLICK = 0x0405)
        if (lParam == 0x0405) {
            // If budget is exhausted, redirect user to Policy tab
            if (PManContext::Get().subs.budget && PManContext::Get().subs.budget->IsExhausted()) {
                GuiManager::OpenPolicyTab();
            }
        }
        // Double Click -> Open Neural Center
        else if (lParam == WM_LBUTTONDBLCLK) {
            GuiManager::ShowConfigWindow();
            // Suppress the trailing WM_LBUTTONUP that follows this double-click
            // to prevent the menu from popping up over the window.
            SetPropW(hwnd, L"PMan_SuppressMenu", (HANDLE)1);
            return 0;
        }
        else if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            // Check suppression flag
            if (lParam == WM_LBUTTONUP) {
                if (GetPropW(hwnd, L"PMan_SuppressMenu")) {
                    RemovePropW(hwnd, L"PMan_SuppressMenu");
                    return 0;
                }
            }

            SetForegroundWindow(hwnd);

            // Ensure owner window state is current before menu creation
            DarkMode::ApplyToWindow(hwnd);

            HMENU hMenu = CreatePopupMenu();

            // Apply Dark Mode styles to the context menu
            DarkMode::ApplyToMenu(hMenu);

            // --- Icon Management ---
            std::vector<HBITMAP> menuBitmaps;
            bool isDark = DarkMode::IsEnabled();

            auto SetMenuIcon = [&](HMENU hM, UINT id, UINT iconLight, UINT iconDark, bool byPos = false) {
                UINT iconId = isDark ? iconDark : iconLight;
                HBITMAP hBmp = IconToBitmapPARGB32(g_hInst, iconId, 16, 16);
                if (hBmp) {
                    MENUITEMINFOW mii = { sizeof(mii) };
                    mii.fMask = MIIM_BITMAP;
                    mii.hbmpItem = hBmp;
                    SetMenuItemInfoW(hM, id, byPos, &mii);
                    menuBitmaps.push_back(hBmp);
                }
            };

            // 0. PMan Neural Center
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EDIT_CONFIG, L"PMan Neural Center");
            SetMenuIcon(hMenu, ID_TRAY_EDIT_CONFIG, IDI_TRAY_L_CP, IDI_TRAY_D_CP);

            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

            bool paused = g_userPaused.load();

            // 1. Dashboards Submenu
            HMENU hDashMenu = CreatePopupMenu();
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_LIVE_LOG, L"Live Log Viewer");
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_OPEN_DIR, L"Open Log Folder");
            AppendMenuW(hDashMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_EXPORT_LOG, L"Export Authority Log (JSON)");

            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDashMenu, L"Monitor & Logs");
            // Set icon for "Monitor & Logs" (Last item added)
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_LOG, IDI_TRAY_D_LOG, true);

            // --- Theme Selection Submenu ---
            HMENU hThemeMenu = CreatePopupMenu();
            AppendMenuW(hThemeMenu, MF_STRING | (g_iconTheme == L"Default" ? MF_CHECKED : 0), ID_TRAY_THEME_BASE, L"Default (Embedded)");

            std::vector<std::wstring> themes = TrayAnimator::Get().ScanThemes();
            int themeId = ID_TRAY_THEME_BASE + 1;
            for (const auto& theme : themes) {
                bool isSelected = (g_iconTheme == theme);
                AppendMenuW(hThemeMenu, MF_STRING | (isSelected ? MF_CHECKED : 0), themeId++, theme.c_str());
            }
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hThemeMenu, L"Icon Theme");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_THEME, IDI_TRAY_D_THEME, true);

            // 3. Controls Submenu
            HMENU hControlMenu = CreatePopupMenu();
            AppendMenuW(hControlMenu, MF_STRING | (paused ? MF_CHECKED : 0), ID_TRAY_PAUSE, paused ? L"Resume Activity" : L"Pause Activity");

            // Pause Idle Optimization (prevent CPU limiting during background tasks)
            bool idlePaused = g_pauseIdle.load();
            AppendMenuW(hControlMenu, MF_STRING | (idlePaused ? MF_CHECKED : 0), ID_TRAY_PAUSE_IDLE, L"Passive Mode");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            bool awake = g_keepAwake.load();
            AppendMenuW(hControlMenu, MF_STRING | (awake ? MF_CHECKED : 0), ID_TRAY_KEEP_AWAKE, L"Keep System Awake");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            
            // [PATCH] AI Brain Toggle
            bool brainEnabled = PManContext::Get().conf.enableBrain.load();
            AppendMenuW(hControlMenu, MF_STRING | (brainEnabled ? MF_CHECKED : 0), ID_TRAY_TOGGLE_BRAIN, L"Enable AI Governor");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            
            AppendMenuW(hControlMenu, MF_STRING, ID_TRAY_REFRESH_GPU, L"Refresh GPU");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hControlMenu, L"Controls");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_CONTROLS, IDI_TRAY_D_CONTROLS, true);

            // --- Memory Cleaner Submenu ---
            HMENU hCleanerMenu = CreatePopupMenu();
            AppendMenuW(hCleanerMenu, MF_STRING, ID_TRAY_CLEAN_MEM_DEFAULT, L"Clean Memory (Default)");
            AppendMenuW(hCleanerMenu, MF_STRING, ID_TRAY_CLEAN_MEM_AGGRESSIVE, L"Clean Memory (Aggressive)");
            AppendMenuW(hCleanerMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hCleanerMenu, MF_STRING | (TrayAnimator::Get().IsMemMonitorActive(80) ? MF_CHECKED : 0), ID_TRAY_CLEAN_MEM_80, L"Auto-Clean Memory (If > 80% Usage)");
            AppendMenuW(hCleanerMenu, MF_STRING | (TrayAnimator::Get().IsMemMonitorActive(90) ? MF_CHECKED : 0), ID_TRAY_CLEAN_MEM_90, L"Auto-Clean Memory (If > 90% Usage)");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hCleanerMenu, L"Memory Cleaner");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_CLEANMEM, IDI_TRAY_D_CLEANMEM, true);

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
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_STARTUP, IDI_TRAY_D_STARTUP, true);

            // 5. Help Submenu
            HMENU hHelpMenu = CreatePopupMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_HELP_USAGE, L"Help");
            AppendMenuW(hHelpMenu, MF_STRING | (g_isCheckingUpdate.load() ? MF_GRAYED : 0), ID_TRAY_UPDATE, L"Check for Updates");
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_ABOUT, L"About");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"Help");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_HELP, IDI_TRAY_D_HELP, true);

            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SUPPORT, L"Support PMan \u2764\U0001F97A");
            SetMenuIcon(hMenu, ID_TRAY_SUPPORT, IDI_TRAY_L_SUPPORT, IDI_TRAY_D_SUPPORT);

            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
            SetMenuIcon(hMenu, ID_TRAY_EXIT, IDI_TRAY_L_EXIT, IDI_TRAY_D_EXIT);

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
            // hConfigMenu removed
            DestroyMenu(hDashMenu);
            DestroyMenu(hThemeMenu);
            DestroyMenu(hHelpMenu);
            DestroyMenu(hMenu);

            // Cleanup bitmaps
            for (HBITMAP h : menuBitmaps) DeleteObject(h);
        }
        return 0;

    // -----------------------------------------------------------------------
    case WM_COMMAND:
    {
        DWORD wmId = LOWORD(wParam);

        // --- Theme Handler ---
        if (wmId >= ID_TRAY_THEME_BASE && wmId < ID_TRAY_THEME_BASE + 100) {
            std::wstring newTheme = L"Default";
            if (wmId != ID_TRAY_THEME_BASE) {
                std::vector<std::wstring> themes = TrayAnimator::Get().ScanThemes();
                int index = wmId - (ID_TRAY_THEME_BASE + 1);
                if (index >= 0 && index < themes.size()) {
                    newTheme = themes[index];
                }
            }
            TrayAnimator::Get().SetTheme(newTheme);
            SaveIconTheme(newTheme);
        }

        // --- New Handlers ---
        if (wmId == ID_TRAY_LIVE_LOG) {
            GuiManager::ShowLogWindow();
        }
        else if (wmId == ID_TRAY_OPEN_DIR) {
            ShellExecuteW(nullptr, L"open", GetLogPath().c_str(), nullptr, nullptr, SW_SHOW);
        }
        else if (wmId == ID_TRAY_EXPORT_LOG) {
            // Generate timestamped filename
            auto now = std::chrono::system_clock::now();
            auto t   = std::chrono::system_clock::to_time_t(now);
            std::tm tm;
            localtime_s(&tm, &t);

            wchar_t filename[64];
            wcsftime(filename, 64, L"audit_dump_%Y%m%d_%H%M%S.json", &tm);

            std::filesystem::path path = GetLogPath() / filename;

            if (PManContext::Get().subs.provenance) {
                PManContext::Get().subs.provenance->ExportLog(path);

                // Optional: Show balloon tip to confirm
                TrayAnimator::Get().ShowNotification(L"Audit Export Complete", filename, NIIF_INFO);
            }
        }
        else if (wmId == ID_TRAY_EDIT_CONFIG) {
            GuiManager::ShowConfigWindow();
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
            PManContext::Get().isPaused.store(p);

            // --- ANIMATION STATE SWITCH ---
            TrayAnimator::Get().SetPaused(p);
            // -----------------------------

            UpdateTrayTooltip();
            Log(p ? "[USER] Protection PAUSED." : "[USER] Protection RESUMED.");
            if (!p) g_reloadNow.store(true);

            // [PROVENANCE] User override of the Governor must be logged.
            // Sandbox Barrier: we are NOT calling executor.cpp — we set a flag that
            // RunAutonomousCycle reads. The Ledger records the override for audit.
            if (PManContext::Get().subs.provenance) {
                DecisionJustification j{};
                j.actionType            = BrainAction::Maintain;
                j.timestamp             = GetTickCount64();
                j.finalCommitted        = true;
                j.policyHash            = "UserOverride";
                j.sandboxResult.reason  = "UserOverride";
                j.externalVerdict.state = "UserOverride";
                j.externalVerdict.expiresAt = 0;
                j.counterfactuals.push_back({ BrainAction::Maintain, RejectionReason::ManualOverride });
                PManContext::Get().subs.provenance->Record(j);
            }
        }
        else if (wmId == ID_TRAY_PAUSE_IDLE) {
            bool p = !g_pauseIdle.load();
            g_pauseIdle.store(p);

            UpdateTrayTooltip(); // Refresh tooltip immediately

            Log(p ? "[USER] Idle Optimization PAUSED (CPU Limiting Disabled)." : "[USER] Idle Optimization RESUMED.");

            // Immediate effect: If we just paused, force the Idle Manager to think we are active
            // This restores all parked cores instantly.
            if (p) {
                if (PManContext::Get().subs.idle) PManContext::Get().subs.idle->OnIdleStateChanged(false);
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
        else if (wmId == ID_TRAY_TOGGLE_BRAIN) {
            bool brain = !PManContext::Get().conf.enableBrain.load();
            PManContext::Get().conf.enableBrain.store(brain);

            // [FIX] Save directly to disk. Do NOT trigger a full system reload.
            // This prevents the checkmark from being overwritten by the disk config,
            // and stops the Policy/Config reload spam in the logs.
            SaveConfig();

            Log(brain ? "[USER] Autonomous Brain ENABLED (Dynamic Machine Learning Active)." 
                      : "[USER] Autonomous Brain DISABLED (Deterministic Core Engine Mode Active).");
            UpdateTrayTooltip();
        }
        else if (wmId >= ID_TRAY_CLEAN_MEM_DEFAULT && wmId <= ID_TRAY_CLEAN_MEM_90) {
            bool isAggressive = (wmId == ID_TRAY_CLEAN_MEM_AGGRESSIVE);
            DWORD threshold = 0;
            if (wmId == ID_TRAY_CLEAN_MEM_80) threshold = 80;
            if (wmId == ID_TRAY_CLEAN_MEM_90) threshold = 90;

            if (threshold > 0) {
                // Toggle continuous auto-monitor for 80% / 90%
                if (TrayAnimator::Get().IsMemMonitorActive(threshold)) {
                    Log("[USER] Auto Memory Monitor DISABLED (" + std::to_string(threshold) + "%).");
                    PManContext::Get().workerQueue.Push([]() {
                        TrayAnimator::Get().StopMemMonitor();
                    });
                } else {
                    Log("[USER] Auto Memory Monitor ENABLED at " + std::to_string(threshold) + "%.");
                    PManContext::Get().workerQueue.Push([threshold]() {
                        TrayAnimator::Get().StartMemMonitor(threshold);
                    });
                }
            } else {
                // Default / Aggressive — one-shot clean (unchanged behaviour)
                Log(isAggressive ? "[USER] Triggered Aggressive Memory Clean."
                                 : "[USER] Triggered Default Memory Clean.");
                PManContext::Get().workerQueue.Push([isAggressive]() {
                    ULONGLONG freedBytes = PerformClean(isAggressive, false);
                    double freedMB = static_cast<double>(freedBytes) / (1024.0 * 1024.0);
                    wchar_t msg[128];
                    swprintf_s(msg, 128, L"Memory clean completed.\nFreed: %.2f MB", freedMB);
                    TrayAnimator::Get().ShowNotification(L"Memory Cleaner", msg, NIIF_INFO);
                    Log("[MEM] Manual clean freed " + std::to_string(freedMB) + " MB");
                });
            }
        }
        return 0;
    } // End of WM_COMMAND Block

    case WM_POWERBROADCAST:
        if (wParam == PBT_APMQUERYSUSPEND || wParam == PBT_APMSUSPEND)
        {
            Log("System suspending - pausing operations to prevent memory corruption");
            g_isSuspended.store(true);
        }
        else if (wParam == PBT_APMRESUMEAUTOMATIC || wParam == PBT_APMRESUMESUSPEND)
        {
            Log("System resumed - waiting 5s for kernel stability");

            // State-based delay instead of detached thread
            g_resumeStabilizationTime = GetTickCount64() + 5000;
            g_isSuspended.store(true); // Keep suspended until stabilization
        }
        else if (wParam == PBT_POWERSETTINGCHANGE)
        {
            g_reloadNow = true;
        }
        return 0;
    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

// ---------------------------------------------------------------------------
// Tray status helpers — moved from main.cpp
// ---------------------------------------------------------------------------
void UpdateTrayTooltip()
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

    // 3. Current Mode
    if (g_sessionLocked.load()) {
         tip += L"\n\u1F3AE Mode: Gaming";
    }

    // 4. Brain Status
    if (!PManContext::Get().conf.enableBrain.load()) {
         tip += L"\n\u2699 Brain: OFF (Core Engine Mode)";
    }

    // SRAM Status
    LagState sramState = SramEngine::Get().GetStatus().state;
    if (sramState == LagState::SNAPPY) tip += L"\n\u26A1 System: Snappy";
    else if (sramState == LagState::SLIGHT_PRESSURE) tip += L"\n\u26A0 System: Pressure";
    else if (sramState == LagState::LAGGING) tip += L"\n\u26D4 System: Lagging";
    else if (sramState == LagState::CRITICAL_LAG) tip += L"\n\u2620 System: CRITICAL";

    // Delegate to module
    TrayAnimator::Get().UpdateTooltip(tip);
}

void ShowSramNotification(LagState state)
{
    if (state <= LagState::SLIGHT_PRESSURE) return; // Don't annoy user for minor things

    // Rate Limit: Max 1 notification every 30 seconds
    static uint64_t lastNotify = 0;
    uint64_t now = GetTickCount64();
    if (now - lastNotify < 30000) return;
    lastNotify = now;

    std::wstring title = L"System Responsiveness Alert";
    std::wstring msg = L"";

    DWORD flags = NIIF_NONE;
    if (state == LagState::LAGGING) {
        msg = L"System is experiencing lag. Optimization scans have been deferred to restore responsiveness.";
        flags = NIIF_WARNING;
    } else if (state == LagState::CRITICAL_LAG) {
        msg = L"CRITICAL LAG DETECTED. Entering 'Do No Harm' mode. All background operations stopped.";
        flags = NIIF_ERROR;
    }

    TrayAnimator::Get().ShowNotification(title, msg, flags);
}

void TrayAnimator::SetTheme(const std::wstring& themeName) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (themeName == L"Default") {
        m_currentTheme = L"Default";
        m_activeFrames = m_isPaused ? &m_framesPaused : &m_framesNormal;
    } else {
        LoadCustomFrames(themeName);
        if (!m_framesCustom.empty()) {
            m_currentTheme = themeName;
            m_activeFrames = m_isPaused ? &m_framesCustomPaused : &m_framesCustom;
        } else {
            // Fallback if load failed
            m_currentTheme = L"Default";
            m_activeFrames = m_isPaused ? &m_framesPaused : &m_framesNormal;
        }
    }
    m_currentFrame = 0;
}
