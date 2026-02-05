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

#include "log_viewer.h"
#include "logger.h"
#include "dark_mode.h"
#include "utils.h"
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <commctrl.h>
#include <uxtheme.h>

// Internal state
static HWND g_hLogWindow = nullptr;
static HINSTANCE g_hInstLocal = nullptr;

void LogViewer::Register(HINSTANCE hInst) {
    g_hInstLocal = hInst;
    WNDCLASSW wc = {};
    wc.lpfnWndProc = Proc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"PManLogViewer";
    // Ensure IDI_ICON1 or similar is available, or use default
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(101)); 
    RegisterClassW(&wc);
}

void LogViewer::Show(HWND hOwner) {
    if (g_hLogWindow) {
        if (IsIconic(g_hLogWindow)) ShowWindow(g_hLogWindow, SW_RESTORE);
        SetForegroundWindow(g_hLogWindow);
        return;
    }
    
    // Fallback if Register wasn't called or g_hInstLocal is null
    HINSTANCE hInst = g_hInstLocal ? g_hInstLocal : GetModuleHandle(nullptr);

    g_hLogWindow = CreateWindowW(L"PManLogViewer", L"Priority Manager - Live Log",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        hOwner, nullptr, hInst, nullptr);

    // Unified Dark Mode Application
    DarkMode::ApplyToWindow(g_hLogWindow);

    ShowWindow(g_hLogWindow, SW_SHOW);
    // [FIX] Force flush buffered logs to disk immediately when Viewer opens.
    FlushLogger();
}

void LogViewer::RefreshTheme() {
    if (g_hLogWindow) {
        DarkMode::ApplyToWindow(g_hLogWindow);
    }
}

bool LogViewer::IsVisible() {
    return (g_hLogWindow != nullptr) && IsWindowVisible(g_hLogWindow);
}

LRESULT CALLBACK LogViewer::Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    static HFONT hFont;
    static UINT_PTR hTimer;
    static std::streampos lastPos = 0;

    switch (uMsg) {
    case WM_CREATE: {
        hEdit = CreateWindowW(L"EDIT", nullptr,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 0, 0, 0, hwnd, (HMENU)1, g_hInstLocal, nullptr);
        
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
    case WM_TIMER: // Fallthrough
    // Note: WM_LOG_UPDATED should be defined in a shared header (e.g. constants.h)
    // For now assuming 0x0400 + X or reusing logic if defined elsewhere.
    case 0x0400 + 2: // WM_LOG_UPDATED placeholder if not visible here
        UpdateLog(hEdit, lastPos);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, hTimer);
        DeleteObject(hFont);
        g_hLogWindow = nullptr;
        lastPos = 0; 
        return 0;
    }
    // Fix: Explicitly use DefWindowProcW to prevent title truncation
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void LogViewer::UpdateLog(HWND hEdit, std::streampos& lastPos) {
    // Requires GetLogPath() from utils.h or logger.h
    std::filesystem::path logPath = GetLogPath() / L"log.txt";
    
    // RAII Handle
    // Note: Using raw Handle here for read speed, but effectively RAII via CloseHandle in destructor if wrapped
    // Using UniqueHandle from utils.h if available, else raw for snippet
    // Assuming UniqueHandle is available via utils.h
    UniqueHandle hFile(CreateFileW(logPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    
    if (hFile.get() == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER size;
    GetFileSizeEx(hFile.get(), &size);

    if (size.QuadPart < lastPos) lastPos = 0;

    if (size.QuadPart > lastPos) {
        DWORD bytesToRead = (DWORD)(size.QuadPart - lastPos);
        if (bytesToRead > 65536 && lastPos == 0) {
            lastPos = size.QuadPart - 65536;
            bytesToRead = 65536;
        }

        std::vector<char> buffer(bytesToRead + 1);
        LARGE_INTEGER move; move.QuadPart = lastPos;
        SetFilePointerEx(hFile.get(), move, nullptr, FILE_BEGIN);
        
        DWORD bytesRead = 0;
        if (ReadFile(hFile.get(), buffer.data(), bytesToRead, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            
            int wlen = MultiByteToWideChar(CP_ACP, 0, buffer.data(), bytesRead, nullptr, 0);
            std::vector<wchar_t> wBuffer(wlen + 1);
            MultiByteToWideChar(CP_ACP, 0, buffer.data(), bytesRead, wBuffer.data(), wlen);
            wBuffer[wlen] = L'\0';

            // Append text
            SendMessageW(hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1); // Move to end
            SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)wBuffer.data());
            lastPos += bytesRead;
        }
    }
}
