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

#include "dark_mode.h"
#include <dwmapi.h>
#include <uxtheme.h>
#include <string>
#include <unordered_map>

#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Uxtheme.lib")
#pragma comment(lib, "Advapi32.lib")

namespace DarkMode {

    // --- Undocumented/Semi-Documented Definitions ---
    enum PreferredAppMode {
        AppMode_Default = 0,
        AppMode_AllowDark = 1,
        AppMode_ForceDark = 2,
        AppMode_ForceLight = 3,
        AppMode_Max = 4
    };

    using fnSetPreferredAppMode = PreferredAppMode(WINAPI*)(PreferredAppMode appMode);
    using fnAllowDarkModeForWindow = BOOL(WINAPI*)(HWND hWnd, BOOL allow);
    using fnFlushMenuThemes = void(WINAPI*)();

    // Global Function Pointers
    static fnAllowDarkModeForWindow g_AllowDarkModeForWindow = nullptr;
    static fnSetPreferredAppMode    g_SetPreferredAppMode = nullptr;
    static fnFlushMenuThemes        g_FlushMenuThemes = nullptr;

    // [FIX] State tracking to prevent infinite recursion in WM_THEMECHANGED
    static std::unordered_map<HWND, bool> g_windowState;

    void Initialize() {
        // We load the library but intentionally do NOT free it, 
        // ensuring function pointers remain valid for the app's lifetime.
        HMODULE hUxTheme = LoadLibraryExW(L"uxtheme.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!hUxTheme) return;

        // Ordinal 135: SetPreferredAppMode
        g_SetPreferredAppMode = reinterpret_cast<fnSetPreferredAppMode>(
            GetProcAddress(hUxTheme, MAKEINTRESOURCEA(135)));

        // Ordinal 133: AllowDarkModeForWindow
        g_AllowDarkModeForWindow = reinterpret_cast<fnAllowDarkModeForWindow>(
            GetProcAddress(hUxTheme, MAKEINTRESOURCEA(133)));

        // Ordinal 136: FlushMenuThemes
        g_FlushMenuThemes = reinterpret_cast<fnFlushMenuThemes>(
            GetProcAddress(hUxTheme, MAKEINTRESOURCEA(136)));

        if (g_SetPreferredAppMode) {
            g_SetPreferredAppMode(AppMode_AllowDark); // FOLLOW SYSTEM
        }
    }

    bool IsEnabled() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            DWORD value = 0;
            DWORD size = sizeof(value);
            if (RegQueryValueExW(hKey, L"AppsUseLightTheme", nullptr, nullptr,
                (LPBYTE)&value, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return (value == 0); // 0 = Dark Mode, 1 = Light Mode
            }
            RegCloseKey(hKey);
        }
        return false; // Default to Light Mode
    }

    void ApplyToWindow(HWND hWnd) {
        bool useDarkMode = IsEnabled();

        // [FIX] Check if we have already applied this state to this window.
        // If the requested state matches the current state, DO NOT call SetWindowTheme.
        // This prevents the WM_THEMECHANGED -> ApplyToWindow -> SetWindowTheme -> WM_THEMECHANGED loop.
        if (g_windowState.find(hWnd) != g_windowState.end()) {
            if (g_windowState[hWnd] == useDarkMode) {
                return; // Already set, exit to prevent recursion
            }
        }
        
        // Update state cache
        g_windowState[hWnd] = useDarkMode;

        BOOL bDarkMode = useDarkMode ? TRUE : FALSE;

        // 1. DWM Title Bar (Safe to call repeatedly, but good to gate)
        DwmSetWindowAttribute(hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &bDarkMode, sizeof(bDarkMode));

        // 2. Undocumented Hook
        if (g_AllowDarkModeForWindow) {
            g_AllowDarkModeForWindow(hWnd, bDarkMode);
        }

        // 3. Common Controls Theme (Triggers WM_THEMECHANGED)
        SetWindowTheme(hWnd, useDarkMode ? L"DarkMode_Explorer" : L"Explorer", nullptr);

        // 4. Force Frame Refresh (Future-Proofing for DWM)
        SetWindowPos(hWnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }

    void ApplyToMenu(HMENU hMenu) {
        if (IsEnabled()) {
            MENUINFO mi = { sizeof(MENUINFO) };
            mi.fMask = MIM_STYLE | MIM_APPLYTOSUBMENUS;
            mi.dwStyle = MNS_CHECKORBMP | MNS_AUTODISMISS;
            SetMenuInfo(hMenu, &mi);
        }
    }

    void RefreshTheme() {
        if (g_FlushMenuThemes) {
            g_FlushMenuThemes();
        }
    }
}
