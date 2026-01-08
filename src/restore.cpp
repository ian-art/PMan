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

#include "restore.h"
#include "logger.h"
#include "globals.h" // For g_caps
#include "utils.h"   // For UniqueRegKey
#include <windows.h>
#include <srrestoreptapi.h>
#include <string>

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

static bool CreateRestorePoint()
{
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
