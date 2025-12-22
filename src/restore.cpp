#include "restore.h"
#include "logger.h"
#include "globals.h" // For g_caps
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
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD val = 0;
    DWORD size = sizeof(val);
    LONG result = RegQueryValueExW(hKey, REG_VALUE_NAME, nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);
    RegCloseKey(hKey);

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
    // 1. Load the library dynamically
    HMODULE hSrClient = LoadLibraryW(L"srclient.dll");
    if (!hSrClient)
    {
        Log("[BACKUP] System Restore service (srclient.dll) not found - skipping backup");
        return false;
    }

    // 2. Get the function address
    auto pSRSetRestorePointW = reinterpret_cast<SRSetRestorePointWPtr>(
        GetProcAddress(hSrClient, "SRSetRestorePointW"));

    if (!pSRSetRestorePointW)
    {
        Log("[BACKUP] SRSetRestorePointW entry point not found");
        FreeLibrary(hSrClient);
        return false;
    }

    // 3. Prepare the structure
    RESTOREPOINTINFOW restorePt = {0};
    restorePt.dwEventType = BEGIN_SYSTEM_CHANGE;
    restorePt.dwRestorePtType = APPLICATION_INSTALL; // OR MODIFY_SETTINGS
    restorePt.llSequenceNumber = 0;
    wcscpy_s(restorePt.szDescription, L"Priority Manager First Run");

    STATEMGRSTATUS smStatus = {0};

    Log("[BACKUP] Attempting to create System Restore point...");

    // 4. Call the API
    if (pSRSetRestorePointW(&restorePt, &smStatus))
    {
        // Must call END_SYSTEM_CHANGE to finalize it
        restorePt.dwEventType = END_SYSTEM_CHANGE;
        restorePt.llSequenceNumber = smStatus.llSequenceNumber;
        
        if (pSRSetRestorePointW(&restorePt, &smStatus))
        {
            Log("[BACKUP] System Restore point created successfully.");
            FreeLibrary(hSrClient);
            return true;
        }
    }

    DWORD err = smStatus.nStatus; // Status from the manager
    if (err == 0) err = GetLastError();

    Log("[BACKUP] Failed to create restore point. Status: " + std::to_string(err));
    
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
        // Optional: If you want to retry on next launch if it failed, do nothing here.
        // give up and stop trying (to prevent boot delays)
        MarkRestorePointAsCreated(); 
    }
}