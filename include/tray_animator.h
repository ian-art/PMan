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

#ifndef PMAN_TRAY_ANIMATOR_H
#define PMAN_TRAY_ANIMATOR_H

#include <windows.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <mutex>
#include <memory>

class TrayAnimator {
public:
    static TrayAnimator& Get();

    // Lifecycle
    void Initialize(HINSTANCE hInstance, HWND hwnd);
    void Shutdown();
    
    // Event Handlers
    void OnTimer(WPARAM timerId);
    void OnTaskbarRestart();
    
    // Control
    void SetTheme(const std::wstring& themeName);
    void SetPaused(bool paused);
    void UpdateTooltip(const std::wstring& text);
    void ShowNotification(const std::wstring& title, const std::wstring& msg, DWORD flags);
    
    // Helpers
    std::vector<std::wstring> ScanThemes();

private:
    TrayAnimator();
    ~TrayAnimator();
    
    void LoadResources();
    void LoadCustomFrames(const std::wstring& themeName);
    void EnsureCustomFolder();
    void UpdateIcon();
    void FreeIcons(std::vector<HICON>& icons);

    HINSTANCE m_hInst = nullptr;
    HWND m_hwnd = nullptr;
    NOTIFYICONDATAW m_nid = {};
    
    std::vector<HICON> m_framesNormal;
    std::vector<HICON> m_framesPaused;
    std::vector<HICON> m_framesCustom;
    std::vector<HICON> m_framesCustomPaused;
    
    std::vector<HICON>* m_activeFrames = nullptr;
    size_t m_currentFrame = 0;
    
    bool m_isPaused = false;
    bool m_initialized = false;
    std::wstring m_currentTheme = L"Default";
    std::mutex m_mtx; // Protect resource swapping

    // Constants
    static const UINT TIMER_ID = 9001; // Unique ID to avoid collision
    static const UINT ICON_UID = 1001; // Internal ID for Shell_NotifyIcon
};

#endif // PMAN_TRAY_ANIMATOR_H
