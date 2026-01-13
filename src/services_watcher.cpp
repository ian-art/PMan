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

#include "services_watcher.h"
#include "services.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include <vector>
#include <algorithm>

void ServiceWatcher::Initialize() {
    Log("[WATCHER] Service Watcher initialized (Mode: Auto-Trim Manual Services)");
}

// Static atomic guard to prevent thread stacking
static std::atomic<bool> s_scanInProgress{false};

void ServiceWatcher::OnTick() {
    if (!g_suspendUpdatesDuringGames.load()) return;

    static uint64_t lastCheck = 0;
    uint64_t now = GetTickCount64();
    if (now - lastCheck < 30000) return; 

    // Skip if previous scan is still running
    if (s_scanInProgress.exchange(true)) return;

    lastCheck = now;

    // FIX: Offload SCM operations to background thread to prevent Main Thread lag
    std::thread([]{
        ScanAndTrimManualServices();
        s_scanInProgress.store(false); // Release lock
    }).detach();
}

// Check if other running services depend on this one
static bool HasActiveDependents(SC_HANDLE hSvc) {
    DWORD bytesNeeded = 0;
    DWORD count = 0;
    
    // First call to determine buffer size
    EnumDependentServicesW(hSvc, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count);
    
    if (GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0) {
        // If we have data, it means there ARE active dependents
        return true; 
    }
    return false;
}

void ServiceWatcher::ScanAndTrimManualServices() {
    SC_HANDLE hSc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSc) return;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    EnumServicesStatusExW(hSc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSc);
        return;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExW(hSc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr))
    {
        LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

        for (DWORD i = 0; i < servicesReturned; i++) {
            std::wstring svcName = services[i].lpServiceName;
            DWORD pid = services[i].ServiceStatusProcess.dwProcessId;

            if (services[i].ServiceStatusProcess.dwCurrentState != SERVICE_RUNNING) continue;
            
            // 1. Safety: Check Central Critical Whitelist
            if (g_serviceManager.IsCriticalService(svcName)) continue;

            SC_HANDLE hSvc = OpenServiceW(hSc, svcName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_ENUMERATE_DEPENDENTS);
            if (!hSvc) {
                 // Log failure for debugging (Review Point 3)
                 // Log("[WATCHER] Failed to open " + WideToUtf8(svcName.c_str()));
                 continue;
            }

            // 2. Safety: Check Dependencies (Review Point A)
            if (HasActiveDependents(hSvc)) {
                CloseServiceHandle(hSvc);
                continue;
            }

            DWORD configSize = 0;
            QueryServiceConfigW(hSvc, nullptr, 0, &configSize);
            
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> cfgBuf(configSize);
                LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfgBuf.data());
                
                if (QueryServiceConfigW(hSvc, config, configSize, &configSize)) {
                    
                    // 3. Logic: Manual Start?
                    if (config->dwStartType == SERVICE_DEMAND_START) {
                        
                        // 4. Heuristic: Is it truly idle?
                        // FIX: Removed Sleep(500) and double-check to prevent blocking the Main UI Thread.
                        if (IsProcessIdle(pid)) {
                            Log("[AUTO-TRIM] Stopping idle manual service: " + WideToUtf8(svcName.c_str()));
                            
                            // Register & Stop using Operational Bypass
                            if (g_serviceManager.AddService(svcName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP)) {
                                g_serviceManager.SuspendService(svcName, WindowsServiceManager::BypassMode::Operational); 
                            }
                        }
                    }
                }
            }
            CloseServiceHandle(hSvc);
        }
    }
    CloseServiceHandle(hSc);
}

bool ServiceWatcher::IsProcessIdle(DWORD pid) {
    if (pid == 0) return false;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    bool isIdle = false;
    IO_COUNTERS io = {0};

    // Heuristic Improvement (Review Point B): Check IO + CPU
    bool cpuInfo = GetProcessTimes(hProc, &ftCreation, &ftExit, &ftKernel, &ftUser);
    bool ioInfo = GetProcessIoCounters(hProc, &io);

    if (cpuInfo && ioInfo) {
        uint64_t k = ((uint64_t)ftKernel.dwHighDateTime << 32) | ftKernel.dwLowDateTime;
        uint64_t u = ((uint64_t)ftUser.dwHighDateTime << 32) | ftUser.dwLowDateTime;
        
        // Thresholds:
        // CPU: < 100ms total (Still mostly unused)
        // IO:  < 500KB total transfer (Hasn't been doing heavy disk work)
        if ((k + u) < 1000000 && (io.ReadTransferCount + io.WriteTransferCount) < (500 * 1024)) {
            isIdle = true;
        }
    }
    
    CloseHandle(hProc);
    return isIdle;
}
