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
#include "constants.h" // For ID_TRAY_APP_ICON if needed
#include <shellapi.h>
#include <filesystem>
#include <fstream>

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
