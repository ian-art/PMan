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

#ifndef PMAN_LOG_VIEWER_H
#define PMAN_LOG_VIEWER_H

#include <windows.h>
#include <ios>

class LogViewer {
    static HWND s_hWnd;
public:
    static void Register(HINSTANCE hInst);
    static void Show(HWND hOwner);
    static void ApplyTheme();
private:
    static LRESULT CALLBACK Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static void UpdateLog(HWND hEdit, std::streampos& lastPos);
};

#endif // PMAN_LOG_VIEWER_H
