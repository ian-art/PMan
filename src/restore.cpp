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
 
#include <windows.h> // Include Windows FIRST to ensure types are available
#include <objbase.h> // Required for StringFromGUID2 and CLSIDFromString
#include "restore.h"
#include "logger.h"
#include "globals.h" // For g_caps
#include "utils.h"   // For UniqueRegKey
#include <string>
#include <srrestoreptapi.h>
#include <vector>
#include <powrprof.h>
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Ole32.lib") // Required for COM functions

// Registry key to track if we've already done the first-run backup
static const wchar_t* REG_KEY_PATH = L"SOFTWARE\\PriorityManager";
static const wchar_t* REG_VALUE_NAME = L"FirstRunRestorePoint";

// Dynamic function pointer definition
typedef BOOL (WINAPI *SRSetRestorePointWPtr)(PRESTOREPOINTINFOW, PSTATEMGRSTATUS);

static bool HasRestorePointBeenCreated()
{
    HKEY rawKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_QUERY_VALUE, &rawKey) != ERROR_SUCCESS)
    {
        return false;
    }
    UniqueRegKey hKey(rawKey);

    DWORD val = 0;
    DWORD size = sizeof(val);
    LONG result = RegQueryValueExW(hKey.get(), REG_VALUE_NAME, nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);

    return (result == ERROR_SUCCESS && val == 1);
}

static void MarkRestorePointAsCreated()
{
    HKEY hKey;
    DWORD disposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, nullptr, 
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disposition) == ERROR_SUCCESS)
    {
        DWORD val = 1;
        RegSetValueExW(hKey, REG_VALUE_NAME, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
        RegCloseKey(hKey);
    }
}

bool CreateRestorePoint()
{
    // Fix: Ensure System Restore Service (srservice) is enabled and running
    // This resolves Error 1058 (ERROR_SERVICE_DISABLED)
    {
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (hSCM)
        {
            SC_HANDLE hSvc = OpenServiceW(hSCM, L"srservice", 
                SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_START);
            if (hSvc)
            {
                // 1. Enable service if disabled (Set to DEMAND_START)
                ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 
                    SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                
                // 2. Start service if stopped
                SERVICE_STATUS_PROCESS ssp = {};
                DWORD bytesNeeded = 0;
                if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
                {
                    if (ssp.dwCurrentState == SERVICE_STOPPED)
                    {
                        StartServiceW(hSvc, 0, nullptr);
                    }
                }
                CloseServiceHandle(hSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    // NOTE:
    // On Windows 10/11, System Restore is managed per-volume.
    // There is NO supported registry switch that force-enables it.
    // SRSetRestorePointW may return success even when a point is skipped.

    // Best-effort: disable restore point frequency throttling
    {
        HKEY hSysRestore;
        if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore",
                0,
                KEY_SET_VALUE,
                &hSysRestore) == ERROR_SUCCESS)
        {
            DWORD zero = 0;

            // 0 = allow multiple restore points per day
            RegSetValueExW(
                hSysRestore,
                L"SystemRestorePointCreationFrequency",
                0,
                REG_DWORD,
                reinterpret_cast<const BYTE*>(&zero),
                sizeof(zero));

            RegCloseKey(hSysRestore);
        }
    }

    // Load srclient.dll dynamically
    HMODULE hSrClient = LoadLibraryW(L"srclient.dll");
    if (!hSrClient)
    {
        Log("[BACKUP] srclient.dll not available. System Restore may be disabled.");
        return false;
    }

    auto pSRSetRestorePointW =
        reinterpret_cast<SRSetRestorePointWPtr>(
            GetProcAddress(hSrClient, "SRSetRestorePointW"));

    if (!pSRSetRestorePointW)
    {
        Log("[BACKUP] SRSetRestorePointW not exported by srclient.dll.");
        FreeLibrary(hSrClient);
        return false;
    }

    RESTOREPOINTINFOW rpInfo = {};
    rpInfo.dwEventType      = BEGIN_SYSTEM_CHANGE;
    rpInfo.dwRestorePtType = APPLICATION_INSTALL;
    rpInfo.llSequenceNumber = 0;
    wcscpy_s(rpInfo.szDescription, L"Priority Manager First Run");

    STATEMGRSTATUS smStatus = {};

    Log("[BACKUP] Requesting System Restore point creation...");

    // BEGIN transaction
    if (!pSRSetRestorePointW(&rpInfo, &smStatus))
    {
        Log("[BACKUP] BEGIN_SYSTEM_CHANGE rejected. Status: " +
            std::to_string(smStatus.nStatus));
        FreeLibrary(hSrClient);
        return false;
    }

    // END transaction (finalizes request)
    rpInfo.dwEventType = END_SYSTEM_CHANGE;
    rpInfo.llSequenceNumber = smStatus.llSequenceNumber;

    if (!pSRSetRestorePointW(&rpInfo, &smStatus))
    {
        Log("[BACKUP] END_SYSTEM_CHANGE failed. Status: " +
            std::to_string(smStatus.nStatus));
        FreeLibrary(hSrClient);
        return false;
    }

    /*
        IMPORTANT:
        SRSetRestorePointW returning success does NOT guarantee
        that a restore point was created.

        Common reasons for silent skip:
        - System Protection disabled on the system volume
        - Restore point frequency throttling
        - Insufficient disk space
        - Group Policy restrictions
        - Concurrent restore activity
    */

    if (smStatus.nStatus == ERROR_SUCCESS)
    {
        Log("[BACKUP] Restore point request accepted by System Restore.");
        FreeLibrary(hSrClient);
        return true;
    }

    Log("[BACKUP] Restore point request completed with status: " +
        std::to_string(smStatus.nStatus));

    FreeLibrary(hSrClient);
    return false;
}


void EnsureStartupRestorePoint()
{
    // Requires Admin rights to write to HKLM and trigger System Restore
    if (!g_caps.hasAdminRights) 
    {
        // Silent return, we can't do it anyway
        return;
    }

    if (HasRestorePointBeenCreated())
    {
        return;
    }

	// Attempt creation
    if (CreateRestorePoint())
    {
        MarkRestorePointAsCreated();
    }
    else
    {
        // Fix Do NOT mark as created on failure, so we retry next time
        Log("[BACKUP] Restore point creation failed. Will retry on next startup.");
    }
}

// --- Service Watchdog ("Dead Man's Switch") ---
void RunRegistryGuard(DWORD targetPid, DWORD lowTime, DWORD highTime, DWORD originalVal, const std::wstring& startupPowerScheme)
{
    // 1. Wait for the main process to exit (crash, kill, or close)
    HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (hProcess)
    {
        // Verify process identity using creation time to prevent PID reuse
        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser))
        {
            if (ftCreation.dwLowDateTime == lowTime && ftCreation.dwHighDateTime == highTime)
            {
                WaitForSingleObject(hProcess, INFINITE);
            }
        }
        CloseHandle(hProcess);
    }

    // 2. Check if registry was left in a modified state
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
        0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) == ERROR_SUCCESS)
    {
        DWORD currentVal = 0;
        DWORD size = sizeof(currentVal);
        if (RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, 
            reinterpret_cast<BYTE*>(&currentVal), &size) == ERROR_SUCCESS)
        {
            if (currentVal != originalVal)
            {
                RegSetValueExW(key, L"Win32PrioritySeparation", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&originalVal), sizeof(originalVal));
                Log("[GUARD] Main process crash detected. Registry Restored.");
            }
        }
        RegCloseKey(key);
    }

    // 3. Power Plan Safety Check
    if (!startupPowerScheme.empty())
    {
        GUID* pCurrentScheme = nullptr;
        if (PowerGetActiveScheme(NULL, &pCurrentScheme) == ERROR_SUCCESS)
        {
            wchar_t currentGuidStr[64] = {};
            if (StringFromGUID2(*pCurrentScheme, currentGuidStr, 64) == 0) currentGuidStr[0] = L'\0';

            if (_wcsicmp(currentGuidStr, startupPowerScheme.c_str()) != 0)
            {
                 GUID originalGuid;
                 if (CLSIDFromString(startupPowerScheme.c_str(), &originalGuid) == S_OK)
                 {
                     PowerSetActiveScheme(NULL, &originalGuid);
                     Log("[GUARD] Crash detected. Restored original Power Plan.");
                 }
            }
            LocalFree(pCurrentScheme);
        }
    }

    // 4. CRITICAL: Check and resume suspended services
    Log("[GUARD] Checking for stranded suspended services...");
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scManager) 
    {
        auto CheckAndResume = [&](const wchar_t* name) {
            SC_HANDLE hSvc = OpenServiceW(scManager, name, SERVICE_QUERY_STATUS | SERVICE_START);
            if (hSvc) {
                SERVICE_STATUS status;
                if (QueryServiceStatus(hSvc, &status) && status.dwCurrentState == SERVICE_STOPPED) {
                    DWORD configSize = 0;
                    // FIX: Explicitly check for expected failure (C6031)
                    if (!QueryServiceConfigW(hSvc, nullptr, 0, &configSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        std::vector<BYTE> buffer(configSize);
                        LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
                        if (QueryServiceConfigW(hSvc, config, configSize, &configSize)) {
                            if (config->dwStartType != SERVICE_DISABLED) {
                                StartServiceW(hSvc, 0, nullptr);
                                Log("[GUARD] Service restored: " + WideToUtf8(name));
                            }
                        }
                    }
                }
                CloseServiceHandle(hSvc);
            }
        };

        CheckAndResume(L"BITS");
        CheckAndResume(L"wuauserv");
        CheckAndResume(L"dosvc");
        CheckAndResume(L"clicktorunsvc");

        CloseServiceHandle(scManager);
    }
}

void LaunchRegistryGuard(DWORD originalVal)
{
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    GetProcessTimes(GetCurrentProcess(), &ftCreation, &ftExit, &ftKernel, &ftUser);

    std::wstring powerGuidStr = L"";
    GUID* pStartupScheme = nullptr;
    if (PowerGetActiveScheme(NULL, &pStartupScheme) == ERROR_SUCCESS)
    {
        wchar_t buf[64] = {};
        if (StringFromGUID2(*pStartupScheme, buf, 64) != 0) powerGuidStr = buf;
        LocalFree(pStartupScheme);
    }

    std::wstring cmd = L"\"" + std::wstring(selfPath) + L"\" --guard " +
                       std::to_wstring(GetCurrentProcessId()) + L" " +
                       std::to_wstring(ftCreation.dwLowDateTime) + L" " +
                       std::to_wstring(ftCreation.dwHighDateTime) + L" " +
                       std::to_wstring(originalVal) + L" \"" +
                       powerGuidStr + L"\"";

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW | DETACHED_PROCESS, 
                       nullptr, nullptr, &si, &pi))
    {
        SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Log("[GUARD] Safety guard launched.");
    }
}
