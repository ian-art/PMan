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

#include "editor_manager.h"
#include "constants.h"
#include "utils.h"
#include "logger.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <vector>

namespace EditorManager {

    namespace {
        // RAII Wrapper for HKEY to ensure cleanup
        class RegKey {
            HKEY hKey = nullptr;
        public:
            RegKey(HKEY root, const std::wstring& subKey, REGSAM access) {
                RegOpenKeyExW(root, subKey.c_str(), 0, access, &hKey);
            }
            ~RegKey() {
                if (hKey) RegCloseKey(hKey);
            }
            // Non-copyable
            RegKey(const RegKey&) = delete;
            RegKey& operator=(const RegKey&) = delete;
            
            operator HKEY() const { return hKey; }
            bool IsValid() const { return hKey != nullptr; }
        };

        std::wstring GetAppPathFromReg(const wchar_t* exeName) {
            const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
            wchar_t buffer[MAX_PATH];

            for (HKEY root : roots) {
                std::wstring keyPath = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") + exeName;
                RegKey key(root, keyPath, KEY_QUERY_VALUE);
                
                if (key.IsValid()) {
                    DWORD size = sizeof(buffer);
                    if (RegQueryValueExW(key, nullptr, nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                        return buffer;
                    }
                }
            }
            return L"";
        }

        int FindLineNumber(const std::wstring& filename, const std::wstring& searchString) {
            // FIX: Explicitly convert wstring to filesystem::path
            std::filesystem::path path = std::filesystem::path(GetLogPath()) / filename;
            std::wifstream file(path);
            if (!file) return 0;

            std::wstring line;
            int lineNum = 1;
            while (std::getline(file, line)) {
                if (line.find(searchString) != std::wstring::npos) {
                    return lineNum;
                }
                lineNum++;
            }
            return 0;
        }
    }

    std::wstring GetPreferredEditor() {
        std::wstring path;
        if ((path = GetAppPathFromReg(L"notepad++.exe")) != L"") return path;
        if ((path = GetAppPathFromReg(L"Code.exe")) != L"") return path;
        if ((path = GetAppPathFromReg(L"sublime_text.exe")) != L"") return path;
        return L"";
    }

    std::wstring GetEditorName() {
        std::wstring path = GetPreferredEditor();
        if (path.empty()) return L"";

        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        if (path.find(L"notepad++.exe") != std::wstring::npos) return L" [Notepad++]";
        if (path.find(L"code.exe") != std::wstring::npos) return L" [VS Code]";
        if (path.find(L"sublime_text.exe") != std::wstring::npos) return L" [Sublime]";
        return L" [Editor]";
    }

    void OpenFile(const std::wstring& filename, int jumpToLine, bool forceAdmin) {
        // FIX: Explicitly convert wstring to filesystem::path
        std::filesystem::path path = std::filesystem::path(GetLogPath()) / filename;
        
        if (!std::filesystem::exists(path)) {
            std::ofstream(path) << ""; 
        }

        std::wstring editor = GetPreferredEditor();
        std::wstring params;

        if (!editor.empty()) {
            if (jumpToLine > 0) {
                std::wstring lowerEditor = editor;
                std::transform(lowerEditor.begin(), lowerEditor.end(), lowerEditor.begin(), ::towlower);

                if (lowerEditor.find(L"notepad++.exe") != std::wstring::npos) {
                    params = L"-n" + std::to_wstring(jumpToLine) + L" \"" + path.wstring() + L"\"";
                } else if (lowerEditor.find(L"code.exe") != std::wstring::npos) {
                    params = L"-g \"" + path.wstring() + L":" + std::to_wstring(jumpToLine) + L"\"";
                } else if (lowerEditor.find(L"sublime_text.exe") != std::wstring::npos) {
                    params = L"\"" + path.wstring() + L":" + std::to_wstring(jumpToLine) + L"\"";
                } else {
                    params = L"\"" + path.wstring() + L"\"";
                }
            } else {
                params = L"\"" + path.wstring() + L"\"";
            }

            // [FIX] Use forceAdmin to determine execution verb (removes C4100 warning)
            const wchar_t* verb = forceAdmin ? L"runas" : L"open";
            HINSTANCE res = ShellExecuteW(nullptr, verb, editor.c_str(), params.c_str(), nullptr, SW_SHOW);
            
            if ((intptr_t)res > 32) return; 
        }

        params = L"\"" + path.wstring() + L"\"";
        HINSTANCE res = ShellExecuteW(nullptr, L"runas", L"notepad.exe", params.c_str(), nullptr, SW_SHOW);

        if ((intptr_t)res <= 32) {
            ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOW);
        }
    }

    void OpenConfigAtSection(const std::wstring& sectionName) {
        int line = FindLineNumber(CONFIG_FILENAME, sectionName);
        OpenFile(CONFIG_FILENAME, line);
    }
}
