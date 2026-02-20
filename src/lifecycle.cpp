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
#include <thread> // [PATCH] Required for Async Termination
#include "utils.h" // Assumed to contain UniqueHandle
#include "logger.h"

// [SECURITY] Native Task Scheduler API (Avoids schtasks.exe detection)
#include <taskschd.h>
#include <comdef.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

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
            // [DYNAMIC] Target both the App and its corresponding Watchdog
            // e.g. "Guardian.exe" and "GuardianWatchdog.exe"
            std::wstring watchdogName = std::filesystem::path(selfName).stem().wstring() + L"Watchdog.exe";

            do {
                // Check strict match for Self OR Watchdog
                if (_wcsicmp(pe.szExeFile, selfName.c_str()) == 0 || 
                    _wcsicmp(pe.szExeFile, watchdogName.c_str()) == 0) {

                    // Don't kill ourselves
                    if (pe.th32ProcessID != GetCurrentProcessId()) {
                        // [PATCH] Open with SYNCHRONIZE to ensure WaitForSingleObject works correctly
                        UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID));
                        if (hProc) {
                            TerminateProcess(hProc.get(), 0);
                            // Wait up to 3s to guarantee termination before proceeding
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
        // 1. Dynamic Target Resolution (Preserved)
        std::filesystem::path p(exePath);
        std::wstring watchdogName = p.stem().wstring() + L"Watchdog.exe";
        std::filesystem::path watchdogPath = p.parent_path() / watchdogName;

        std::wstring targetExe = exePath;
        if (std::filesystem::exists(watchdogPath)) {
            targetExe = watchdogPath.wstring();
            Log("[LIFECYCLE] Watchdog detected. Registering supervisor task.");
        }

        std::wstring args = L"/S";
        if (passiveMode) args += L" --paused";

        // 2. Initialize COM
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        bool comInitialized = SUCCEEDED(hr);
        
        // 3. Connect to Task Scheduler Service
        ITaskService *pService = NULL;
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
        if (FAILED(hr)) { if(comInitialized) CoUninitialize(); return false; }

        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) { pService->Release(); if(comInitialized) CoUninitialize(); return false; }

        // 4. Get Root Folder
        ITaskFolder *pRootFolder = NULL;
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr)) { pService->Release(); if(comInitialized) CoUninitialize(); return false; }

        // 5. Delete Existing (Force Overwrite)
        pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);

        // 6. Create Task Definition
        ITaskDefinition *pTask = NULL;
        hr = pService->NewTask(0, &pTask);
        if (FAILED(hr)) { pRootFolder->Release(); pService->Release(); if(comInitialized) CoUninitialize(); return false; }

        // Principal: Highest Privileges (Admin)
        IPrincipal *pPrincipal = NULL;
        if (SUCCEEDED(pTask->get_Principal(&pPrincipal))) {
            pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            pPrincipal->Release();
        }

        // Settings: Power Management (Allow on battery, don't stop)
        ITaskSettings *pSettings = NULL; // [FIX] Correct Interface Name
        if (SUCCEEDED(pTask->get_Settings(&pSettings))) {
            pSettings->put_StartWhenAvailable(VARIANT_TRUE);
            pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // Infinite
            pSettings->Release();
        }

        // Trigger: On Logon
        ITriggerCollection *pTriggerCollection = NULL;
        if (SUCCEEDED(pTask->get_Triggers(&pTriggerCollection))) {
            ITrigger *pTrigger = NULL;
            if (SUCCEEDED(pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger))) {
                pTrigger->Release();
            }
            pTriggerCollection->Release();
        }

        // Action: Execute
        IActionCollection *pActionCollection = NULL;
        if (SUCCEEDED(pTask->get_Actions(&pActionCollection))) {
            IAction *pAction = NULL;
            if (SUCCEEDED(pActionCollection->Create(TASK_ACTION_EXEC, &pAction))) {
                IExecAction *pExecAction = NULL;
                if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction))) {
                    pExecAction->put_Path(_bstr_t(targetExe.c_str()));
                    pExecAction->put_Arguments(_bstr_t(args.c_str()));
                    pExecAction->Release();
                }
                pAction->Release();
            }
            pActionCollection->Release();
        }

        // 7. Register Task
        IRegisteredTask *pRegisteredTask = NULL;
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(taskName.c_str()),
            pTask,
            TASK_CREATE_OR_UPDATE, 
            _variant_t(), 
            _variant_t(), 
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask);

        bool success = SUCCEEDED(hr);
        if (!success) {
            Log("[LIFECYCLE] Failed to register task via COM: " + std::to_string(hr));
        }

        // Cleanup
        if (pRegisteredTask) pRegisteredTask->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        if (comInitialized) CoUninitialize();

        return success;
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
            UniqueHandle hProc(pi.hProcess);
            UniqueHandle hThread(pi.hThread);
            WaitForSingleObject(hProc.get(), 5000);
        }
    }
}
