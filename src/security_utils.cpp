/*
 * This file is part of Priority Manager (PMan).
 *
 * Copyright (c) 2025 Ian Anthony R. Tancinco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "security_utils.h"
#include "utils.h" // Requires GetParentProcessId, GetProcessNameFromPid
#include <vector>
#include <sddl.h>
#include <cwctype>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

namespace SecurityUtils {

bool IsProcessTrusted(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return false;
    }
    CloseHandle(hProcess);

    WINTRUST_FILE_INFO fileData = {0};
    fileData.cbStruct = sizeof(fileData);
    fileData.pcwszFilePath = path;

    WINTRUST_DATA winTrustData = {0};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileData;

    // [FIX] Instantiate GUID to pass by address
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &action, &winTrustData);
    
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &winTrustData);

    return (status == ERROR_SUCCESS);
}

bool IsSystemOrService(HANDLE hToken) {
    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<BYTE> buffer(len);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) return false;

    PTOKEN_USER pUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
    
    // Check against Well-Known SIDs for System Infrastructure
    if (IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid)) return true;
    if (IsWellKnownSid(pUser->User.Sid, WinLocalServiceSid)) return true;
    if (IsWellKnownSid(pUser->User.Sid, WinNetworkServiceSid)) return true;
    
    return false;
}

bool IsProxyLaunch(DWORD pid) {
    if (pid == 0 || pid == 4) return false;

    // 1. Get Parent PID
    DWORD parentPid = GetParentProcessId(pid);
    if (parentPid == 0) return false; // Parent likely dead or protected

    // 2. Check Parent Name (Is it System Infrastructure?)
    std::wstring parentName = GetProcessNameFromPid(parentPid);
    if (parentName.empty()) return false;

    // Normalize for comparison
    for (auto& c : parentName) c = towlower(c);

    // List of common "Living off the Land" binaries used for proxy execution
    bool isSystemInfra = (parentName == L"wmiprvse.exe" || 
                          parentName == L"svchost.exe" || 
                          parentName == L"taskeng.exe" ||
                          parentName == L"services.exe");

    if (!isSystemInfra) return false;

    // 3. Check Child Token (Is it NOT System?)
    // Logic: If WMI (System) launches a script as "User", it is likely malicious/persistence.
    // If WMI launches a child as "System", it is likely standard OS behavior.
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    bool isSafeIdentity = IsSystemOrService(hToken);
    
    CloseHandle(hToken);
    CloseHandle(hProcess);

    // RESULT: Parent is Infra + Child is NOT Infra => PROXY LAUNCH (Probation Required)
    return !isSafeIdentity;
}

}
