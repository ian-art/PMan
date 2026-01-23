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
 
#include <windows.h> // Include Windows FIRST
#include <objbase.h>
#include <wbemidl.h> // WMI Interface
#include <comdef.h>
#include "restore.h"
#include "logger.h"
#include "globals.h" 
#include "utils.h"   
#include <string>
#include <srrestoreptapi.h>
#include <vector>
#include <fstream>
#include <filesystem>
#include <powrprof.h>

#pragma comment(lib, "wbemuuid.lib") // Link WMI
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Ole32.lib") 

// File-based state persistence for robust recovery
static const wchar_t* STATE_FILENAME = L"pman_restore.bin";

// Helper: Get State File Path (Temp Directory)
std::filesystem::path GetStateFilePath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    return std::filesystem::path(tempPath) / STATE_FILENAME;
}

// Helper: RAII Registry Reader
DWORD ReadRegDWORD(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName) {
    HKEY rawKey;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_QUERY_VALUE, &rawKey) != ERROR_SUCCESS) return 0xFFFFFFFF;
    UniqueRegKey hKey(rawKey);
    
    DWORD data = 0;
    DWORD size = sizeof(data);
    if (RegQueryValueExW(hKey.get(), valueName, nullptr, nullptr, (LPBYTE)&data, &size) == ERROR_SUCCESS) {
        return data;
    }
    return 0xFFFFFFFF;
}

// Registry key to track if we've already done startup restore
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

// Native WMI implementation to Enable System Restore without spawning PowerShell
static bool EnableSystemRestoreWMI()
{
    HRESULT hr;
    
    // 1. Initialize COM (Assume already init by Main, but safe to re-init)
    // CoInitializeEx(0, COINIT_MULTITHREADED); // Handled by caller/main

    // 2. Setup WMI Security
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, 
        RPC_C_IMP_LEVEL_IMPERSONATE, 
        NULL, EOAC_NONE, NULL);
    
    // RPC_E_TOO_LATE is fine (security already set)
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) return false;

    // 3. Connect to WMI (Root\Default contains SystemRestore class)
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) return false;

    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\DEFAULT"), 
        NULL, NULL, 0, NULL, 0, 0, &pSvc);

    pLoc->Release();
    if (FAILED(hr)) return false;

    // 4. Set Proxy Blanket (Security on the connection)
    hr = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, 
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (FAILED(hr)) { pSvc->Release(); return false; }

    // 5. Execute "Enable" Method on SystemRestore Class
    // Method Signature: uint32 Enable(String Drive)
    _bstr_t className(L"SystemRestore");
    _bstr_t methodName(L"Enable");

    // Get Class Object to find method definition
    IWbemClassObject* pClass = NULL;
    hr = pSvc->GetObject(className, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) { pSvc->Release(); return false; }

    // Get Method Input Parameters signature
    IWbemClassObject* pInParamsDefinition = NULL;
    hr = pClass->GetMethod(methodName, 0, &pInParamsDefinition, NULL);
    pClass->Release();
    if (FAILED(hr)) { pSvc->Release(); return false; }

    // Create Instance of Input Parameters
    IWbemClassObject* pClassInstance = NULL;
    hr = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
    pInParamsDefinition->Release();
    if (FAILED(hr)) { pSvc->Release(); return false; }

    // Set "Drive" Parameter to "C:\" (System Drive)
    // We assume C:\ for simplicity, or fetch GetSystemDirectory
    wchar_t sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    sysPath[3] = 0; // Truncate to "C:\"

    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(sysPath);
    hr = pClassInstance->Put(L"Drive", 0, &varCommand, 0);

    if (FAILED(hr)) {
        pClassInstance->Release();
        pSvc->Release();
        return false;
    }

    // Execute Method
    IWbemClassObject* pOutParams = NULL;
    hr = pSvc->ExecMethod(className, methodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    // Cleanup
    bool success = SUCCEEDED(hr);
    if (pOutParams) pOutParams->Release();
    pClassInstance->Release();
    pSvc->Release();

    if (success) Log("[BACKUP] System Protection enabled via WMI (AV-Safe)");
    else Log("[BACKUP] Failed to enable System Protection via WMI: 0x" + std::to_string(hr));

    return success;
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

    // Force-Enable System Protection
    {
        if (EnableSystemRestoreWMI()) {
             // Success - proceed immediately
        } else {
             Log("[BACKUP] Warning: Could not enforce System Protection. Restore point creation may fail silently.");
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
// Helper: Restore a DWORD to registry
static void RestoreDwordReg(HKEY root, LPCWSTR subKey, LPCWSTR valueName, DWORD val)
{
    // 0xFFFFFFFF usually implies we shouldn't touch it.
    if (val == 0xFFFFFFFF) return;

    HKEY key;
    if (RegOpenKeyExW(root, subKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegSetValueExW(key, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
        RegCloseKey(key);
    }
}

static void RestoreStringReg(HKEY root, LPCWSTR subKey, LPCWSTR valueName, const wchar_t* val)
{
    if (val[0] == L'\0') return; // Empty/Was missing

    HKEY key;
    if (RegOpenKeyExW(root, subKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegSetValueExW(key, valueName, 0, REG_SZ, (const BYTE*)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
}

void RunRegistryGuard(DWORD targetPid, DWORD lowTime, DWORD highTime, DWORD originalVal, const std::wstring& startupPowerScheme)
{
    // 1. Verify Parent Identity
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, targetPid);
    if (!hProc) return; // Process already gone or inaccessible

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProc, &ftCreation, &ftExit, &ftKernel, &ftUser))
    {
        if (ftCreation.dwLowDateTime != lowTime || ftCreation.dwHighDateTime != highTime)
        {
            CloseHandle(hProc);
            return; // PID reused, not our parent
        }
    }
    else
    {
        CloseHandle(hProc);
        return;
    }

    // 2. Wait for Parent Termination
    // Block indefinitely until PMan exits (cleanly or crash)
    WaitForSingleObject(hProc, INFINITE);
    CloseHandle(hProc);

    // 3. Begin Restoration Transaction
    Sleep(1000); // Allow PMan's own cleanup to race first

    RegistryBackupState state;
    std::filesystem::path backupPath = GetLogPath() / L"pman_restore.bin";
    std::ifstream file(backupPath, std::ios::binary); // <--- File opens here
    bool useFile = false;

    if (file.read(reinterpret_cast<char*>(&state), sizeof(state))) {
        if (state.isValid) useFile = true;
    }
    
    // [FIX] Close the file immediately so we can delete it later
    file.close();

    // --- Restore Priority Separation ---
    DWORD priRestore = useFile ? state.prioritySeparation : originalVal;
    if (priRestore != 0xFFFFFFFF) {
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
            L"Win32PrioritySeparation", priRestore);
    }

    if (useFile) {
        // --- Core System ---
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", 
            L"NetworkThrottlingIndex", state.networkThrottling);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", 
            L"SystemResponsiveness", state.systemResponsiveness);

        // --- Multimedia Tasks ---
        const wchar_t* gamesKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games";
        RestoreDwordReg(HKEY_LOCAL_MACHINE, gamesKey, L"GPU Priority", state.gpuPriority);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, gamesKey, L"Priority", state.gamesPriority);
        RestoreStringReg(HKEY_LOCAL_MACHINE, gamesKey, L"Scheduling Category", state.schedulingCategory);
        RestoreStringReg(HKEY_LOCAL_MACHINE, gamesKey, L"SFIO Priority", state.sfioPriority);

        // --- Kernel & Memory ---
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel", L"CoalescingTimerInterval", state.coalescingTimer);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel", L"DistributeTimers", state.distributeTimers);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"StoreCompression", state.memoryCompression);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"LargeSystemCache", state.largeSystemCache);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"DisablePagingExecutive", state.disablePagingExecutive);
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"Size", state.lanmanServerSize);

        // --- GameDVR ---
        const wchar_t* gameConfigKey = L"System\\GameConfigStore";
        RestoreDwordReg(HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_Enabled", state.gameDvrEnabled);
        RestoreDwordReg(HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_FSEBehaviorMode", state.gameDvrFseBehavior);
        RestoreDwordReg(HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_HonorUserFSEBehaviorMode", state.gameDvrHonorUserFse);
        RestoreDwordReg(HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_DXGIHonorFSEWindowsCompatible", state.gameDvrDxgiHonorFse);
        RestoreDwordReg(HKEY_CURRENT_USER, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR", L"AppCaptureEnabled", state.appCaptureEnabled);
        
        RestoreDwordReg(HKEY_LOCAL_MACHINE, 
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", L"AllowGameDVR", state.allowGameDvrPolicy);

        // --- Restore Power Scheme ---
        if (state.powerSchemeGuid[0] != 0) {
            GUID scheme;
            if (CLSIDFromString(state.powerSchemeGuid, &scheme) == NOERROR) {
                PowerSetActiveScheme(NULL, &scheme);
            }
        }
    }
    else {
        // Fallback: Restore only what was passed on command line (Legacy Mode)
        if (!startupPowerScheme.empty()) {
            GUID scheme;
            if (CLSIDFromString(startupPowerScheme.c_str(), &scheme) == NOERROR) {
                PowerSetActiveScheme(NULL, &scheme);
            }
        }
    }

    // 4. Cleanup
    if (useFile) {
        std::error_code ec;
        std::filesystem::remove(backupPath, ec);
    }
}

// Helper: Read a DWORD from registry safely
static DWORD ReadDwordReg(HKEY root, LPCWSTR subKey, LPCWSTR valueName, DWORD defaultVal)
{
    DWORD data = defaultVal;
    DWORD size = sizeof(data);
    if (RegGetValueW(root, subKey, valueName, RRF_RT_REG_DWORD, nullptr, &data, &size) == ERROR_SUCCESS) {
        return data;
    }
    return defaultVal;
}

static void ReadStringReg(HKEY root, LPCWSTR subKey, LPCWSTR valueName, wchar_t* outBuf, size_t bufSize)
{
    DWORD type = REG_SZ;
    DWORD size = static_cast<DWORD>(bufSize * sizeof(wchar_t));
    if (RegGetValueW(root, subKey, valueName, RRF_RT_REG_SZ, &type, outBuf, &size) != ERROR_SUCCESS) {
        outBuf[0] = L'\0'; // Mark as empty/not found
    }
}

void LaunchRegistryGuard(DWORD originalVal)
{
    // 1. Capture Full Registry State
    RegistryBackupState state{};
    state.isValid = true;
    state.prioritySeparation = originalVal;

    // --- Core System ---
    const wchar_t* systemProfile =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";

    state.networkThrottling = ReadDwordReg(
        HKEY_LOCAL_MACHINE, systemProfile, L"NetworkThrottlingIndex", 10);

    state.systemResponsiveness = ReadDwordReg(
        HKEY_LOCAL_MACHINE, systemProfile, L"SystemResponsiveness", 20);

    // --- Multimedia Tasks (Games) ---
    const wchar_t* gamesKey =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games";

    state.gpuPriority     = ReadDwordReg(HKEY_LOCAL_MACHINE, gamesKey, L"GPU Priority", 8);
    state.gamesPriority  = ReadDwordReg(HKEY_LOCAL_MACHINE, gamesKey, L"Priority", 2);

    ReadStringReg(HKEY_LOCAL_MACHINE, gamesKey,
                  L"Scheduling Category", state.schedulingCategory, 32);

    ReadStringReg(HKEY_LOCAL_MACHINE, gamesKey,
                  L"SFIO Priority", state.sfioPriority, 32);

    // --- Kernel & Memory ---
    const wchar_t* kernelKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";

    const wchar_t* memoryKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

    state.coalescingTimer = ReadDwordReg(
        HKEY_LOCAL_MACHINE, kernelKey, L"CoalescingTimerInterval", 0);

    state.distributeTimers = ReadDwordReg(
        HKEY_LOCAL_MACHINE, kernelKey, L"DistributeTimers", 0);

    state.disablePagingExecutive = ReadDwordReg(
        HKEY_LOCAL_MACHINE, memoryKey, L"DisablePagingExecutive", 0);

    state.largeSystemCache = ReadDwordReg(
        HKEY_LOCAL_MACHINE, memoryKey, L"LargeSystemCache", 0);

    state.memoryCompression = ReadDwordReg(
        HKEY_LOCAL_MACHINE, memoryKey, L"StoreCompression", 1);

    state.lanmanServerSize = ReadDwordReg(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"Size", 1);

    // --- GameDVR (HKCU) ---
    const wchar_t* gameConfigKey = L"System\\GameConfigStore";

    state.gameDvrEnabled = ReadDwordReg(
        HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_Enabled", 1);

    state.gameDvrFseBehavior = ReadDwordReg(
        HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_FSEBehaviorMode", 0);

    state.gameDvrHonorUserFse = ReadDwordReg(
        HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_HonorUserFSEBehaviorMode", 0);

    state.gameDvrDxgiHonorFse = ReadDwordReg(
        HKEY_CURRENT_USER, gameConfigKey, L"GameDVR_DXGIHonorFSEWindowsCompatible", 0);

    state.appCaptureEnabled = ReadDwordReg(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
        L"AppCaptureEnabled", 1);

    // --- Policies ---
    state.allowGameDvrPolicy = ReadDwordReg(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
        L"AllowGameDVR", 1);

    // --- Power Scheme ---
    GUID* pStartupScheme = nullptr;
    if (PowerGetActiveScheme(nullptr, &pStartupScheme) == ERROR_SUCCESS)
    {
        // Fix C6031: Validate GUID string conversion
        if (StringFromGUID2(*pStartupScheme, state.powerSchemeGuid, 64) == 0)
        {
            state.powerSchemeGuid[0] = L'\0'; // Ensure valid state on failure
        }
        LocalFree(pStartupScheme);
    }

    // 2. Serialize to Disk (Transaction Log)
    const std::filesystem::path backupPath =
        GetLogPath() / L"pman_restore.bin";

    if (std::ofstream file(backupPath, std::ios::binary); file)
    {
        file.write(reinterpret_cast<const char*>(&state), sizeof(state));
    }
    else
    {
        Log("[GUARD] Warning: Failed to write restore state file.");
    }

    // 3. Launch Watchdog Process
    wchar_t selfPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    FILETIME ftCreation{}, ftExit{}, ftKernel{}, ftUser{};
    GetProcessTimes(GetCurrentProcess(), &ftCreation, &ftExit, &ftKernel, &ftUser);

    std::wstring cmd =
        L"\"" + std::wstring(selfPath) + L"\" --guard " +
        std::to_wstring(GetCurrentProcessId()) + L" " +
        std::to_wstring(ftCreation.dwLowDateTime) + L" " +
        std::to_wstring(ftCreation.dwHighDateTime) + L" " +
        std::to_wstring(originalVal) + L" \"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};

    if (CreateProcessW(
            nullptr,
            cmd.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB,
            nullptr,
            nullptr,
            &si,
            &pi))
    {
        Log("[GUARD] Registry Safety Guard launched (PID " +
            std::to_string(pi.dwProcessId) + ")");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        Log("[GUARD] Failed to launch Safety Guard: " +
            std::to_string(GetLastError()));
    }
}

