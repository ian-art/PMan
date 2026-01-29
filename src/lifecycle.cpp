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

#include "lifecycle.h"
#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <vector>
#include "utils.h" // Assumed to contain UniqueHandle
#include "logger.h"

namespace Lifecycle {

    void TerminateExistingInstances() {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        std::wstring selfName = std::filesystem::path(self).filename().wstring();

        // RAII for Snapshot handle
        UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnap.get() == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(hSnap.get(), &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, selfName.c_str()) == 0) {
                    // Don't kill ourselves
                    if (pe.th32ProcessID != GetCurrentProcessId()) {
                        UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID));
                        if (hProc) {
                            TerminateProcess(hProc.get(), 0);
                            WaitForSingleObject(hProc.get(), 3000);
                        }
                    }
                }
            } while (Process32NextW(hSnap.get(), &pe));
        }
    }

    bool IsTaskInstalled(const std::wstring& taskName) {
        std::wstring cmd = L"schtasks /query /tn \"" + taskName + L"\"";
        
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        // Use mutable buffer for CreateProcessW compatibility
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back(0);
        
        if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 
                           CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) {
            return false;
        }

        UniqueHandle hProc(pi.hProcess);
        UniqueHandle hThread(pi.hThread);

        // Wait with timeout to prevent hangs
        if (WaitForSingleObject(hProc.get(), 3000) == WAIT_TIMEOUT) {
            return false;
        }

        DWORD exitCode = 0;
        GetExitCodeProcess(hProc.get(), &exitCode);
        return (exitCode == 0);
    }

    int GetStartupMode(const std::wstring& taskName) {
        if (!IsTaskInstalled(taskName)) return 0; // Disabled

        // Check for --paused flag in the task XML definition
        std::wstring cmd = L"cmd /c schtasks /query /tn \"" + taskName + L"\" /xml | findstr /C:\"--paused\"";
        
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back(0);

        if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            
            UniqueHandle hProc(pi.hProcess);
            UniqueHandle hThread(pi.hThread);

            WaitForSingleObject(hProc.get(), 3000);
            DWORD exitCode = 1;
            GetExitCodeProcess(hProc.get(), &exitCode);

            // findstr returns 0 if found (Paused/Passive), 1 if not found (Active)
            return (exitCode == 0) ? 2 : 1;
        }
        return 1; // Default to Active if check fails but task exists
    }

    bool InstallTask(const std::wstring& taskName, const std::wstring& exePath, bool passiveMode) {
        // Base arguments: Silent only. Passive mode adds --paused
        std::wstring args = L" /S";
        if (passiveMode) args += L" --paused";

        // Construct schtasks command
        // /sc onlogon /rl highest /f (Force)
        std::wstring params = L"/create /tn \"" + taskName + L"\" /tr \"\\\"" + exePath + L"\\\"" + args + L"\" /sc onlogon /rl highest /f";
        
        // Execute as Admin via ShellExecute (Trigger UAC if needed)
        HINSTANCE res = ShellExecuteW(nullptr, L"runas", L"schtasks.exe", params.c_str(), nullptr, SW_HIDE);
        return ((intptr_t)res > 32);
    }

    void UninstallTask(const std::wstring& taskName) {
        std::wstring params = L"/delete /tn \"" + taskName + L"\" /f";
        
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        std::wstring cmd = L"schtasks.exe " + params;
        std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back(0);

        if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
