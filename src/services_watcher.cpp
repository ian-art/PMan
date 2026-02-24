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
#include <thread> // Fix: Needed for std::thread
#include <atomic> // Fix: Needed for std::atomic

void ServiceWatcher::Initialize() {
    Log("[WATCHER] Service Watcher initialized (Mode: Auto-Trim Manual Services)");
}

// Static atomic guard to prevent thread stacking
static std::atomic<bool> s_scanInProgress{false};
static std::thread s_workerThread; // Managed thread handle

// Track suspended services for auto-resume
static std::vector<std::wstring> s_suspendedServices;
static std::mutex s_suspendMtx;

// The Allowlist (Safe & Heavy)
static const std::vector<std::wstring> SAFE_HEAVY_SERVICES = {
    L"SysMain",     // Superfetch (High Disk Usage)
    L"WSearch",     // Windows Search (High CPU/Disk)
    L"DiagTrack",   // Telemetry (Privacy + CPU)
    L"BITS"         // Background Transfer (Bandwidth)
};

void ServiceWatcher::OnTick() {
    if (!g_suspendUpdatesDuringGames.load()) return;

    static uint64_t lastCheck = 0;
    uint64_t now = GetTickCount64();
    // [OPTIMIZATION] Increased interval to 300s (5 minutes) to reduce SCM locking
    if (now - lastCheck < 300000) return; 

    // Skip if previous scan is still running
    if (s_scanInProgress.exchange(true)) return;

    lastCheck = now;

    // Manage thread lifetime (No detach)
    if (s_workerThread.joinable()) {
        s_workerThread.join(); // Clean up previous finished run
    }

    s_workerThread = std::thread([]{
        ScanAndTrimManualServices();
        s_scanInProgress.store(false); // Release lock
    });
}

// Check if other running services depend on this one
static bool HasActiveDependents(SC_HANDLE hSvc) {
    DWORD bytesNeeded = 0;
    DWORD count = 0;
    
    // First call to determine buffer size
    // Fix C6031: Check return (expect failure)
    if (!EnumDependentServicesW(hSvc, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count) && 
        GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0) {
        // If we have data, it means there ARE active dependents
        return true; 
    }
    return false;
}

void ServiceWatcher::ScanAndTrimManualServices() {
    // RAII: Use ScHandle for automatic cleanup
    ScHandle hSc(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT));
    if (!hSc) return;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    // Fix C6031: Check return (expect failure)
    // Use .get() to access raw handle
    if (!EnumServicesStatusExW(hSc.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr) && 
        GetLastError() != ERROR_MORE_DATA) {
        return; // hSc closes automatically
    }

    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExW(hSc.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr))
    {
        LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

        static std::unordered_set<std::wstring> s_rejectionCache;

        for (DWORD i = 0; i < servicesReturned; i++) {
            std::wstring svcName = services[i].lpServiceName;
            DWORD pid = services[i].ServiceStatusProcess.dwProcessId;

            if (services[i].ServiceStatusProcess.dwCurrentState != SERVICE_RUNNING) continue;
            
            // 0. Safety: Check Rejection Cache
            if (s_rejectionCache.count(svcName)) continue;

            // 1. Safety: Check Central Critical Whitelist AND Hard Exclusions
            if (PManContext::Get().subs.serviceMgr) {
                if (PManContext::Get().subs.serviceMgr->IsCriticalService(svcName) || 
                    PManContext::Get().subs.serviceMgr->IsHardExcluded(svcName)) {
                    continue;
                }
            }

            ScHandle hSvc(OpenServiceW(hSc.get(), svcName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_ENUMERATE_DEPENDENTS));
            if (!hSvc) {
                 continue;
            }

            // 2. Safety: Check Dependencies
            if (HasActiveDependents(hSvc.get())) {
                continue; // hSvc closes automatically
            }

            DWORD configSize = 0;
            if (!QueryServiceConfigW(hSvc.get(), nullptr, 0, &configSize) && 
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> cfgBuf(configSize);
                LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfgBuf.data());
                
                if (QueryServiceConfigW(hSvc.get(), config, configSize, &configSize)) {
                    
                    // 3. Logic: Manual Start?
                    if (config->dwStartType == SERVICE_DEMAND_START) {
                        
                        // 4. Heuristic: Is it truly idle?
                        // FIX: Removed Sleep(500) and double-check to prevent blocking the Main UI Thread.
                        if (IsProcessIdle(pid)) {
                            Log("[AUTO-TRIM] Stopping idle manual service: " + WideToUtf8(svcName.c_str()));
                            
                            // Register & Stop using Operational Bypass
                            if (PManContext::Get().subs.serviceMgr) {
                                if (PManContext::Get().subs.serviceMgr->AddService(svcName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP)) {
                                    PManContext::Get().subs.serviceMgr->SuspendService(svcName, WindowsServiceManager::BypassMode::Operational); 
                                } else {
                                    // Cache the rejection to prevent endless polling
                                    s_rejectionCache.insert(svcName);
                                }
                            }
                        }
                    }
                }
            }
            // hSvc closes automatically here
        }
    }
    // hSc closes automatically here
}

bool ServiceWatcher::IsProcessIdle(DWORD pid) {
    if (pid == 0) return false;
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return false;

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    bool isIdle = false;
    IO_COUNTERS io = {0};

    // Heuristic Improvement (Review Point B): Check IO + CPU
    bool cpuInfo = GetProcessTimes(hProc.get(), &ftCreation, &ftExit, &ftKernel, &ftUser);
    bool ioInfo = GetProcessIoCounters(hProc.get(), &io);

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
    
    return isIdle; // hProc closes automatically
}

// --------------------------------------------------------------------------
// Service Muscles Implementation
// --------------------------------------------------------------------------

bool ServiceWatcher::IsSafeToSuspend(const std::wstring& serviceName) {
    // 1. Open Service Manager
    ScHandle hSc(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!hSc) return false;

    // 2. Open Service
    ScHandle hSvc(OpenServiceW(hSc.get(), serviceName.c_str(), SERVICE_ENUMERATE_DEPENDENTS | SERVICE_QUERY_STATUS));
    if (!hSvc) return false;

    // 3. Check Dependencies
    if (HasActiveDependents(hSvc.get())) {
        Log("[SAFETY] Cannot suspend " + WideToUtf8(serviceName.c_str()) + ": Active dependents found.");
        return false;
    }

    return true;
}

// Helper for topological sort
struct ServiceDepNode {
    std::wstring name;
    std::vector<std::wstring> dependencies; // Services that depend ON this node
    bool visited = false;
    bool onStack = false;
};

void ServiceWatcher::SuspendAllowedServices() {
    std::lock_guard<std::mutex> lock(s_suspendMtx);

    // 1. Identify Candidates (Intersection of SafeList and Running Services)
    std::vector<std::wstring> candidates;
    for (const auto& svc : SAFE_HEAVY_SERVICES) {
        if (std::find(s_suspendedServices.begin(), s_suspendedServices.end(), svc) != s_suspendedServices.end()) continue;
        if (!IsSafeToSuspend(svc)) continue; // Basic safety check
        if (PManContext::Get().subs.serviceMgr && PManContext::Get().subs.serviceMgr->IsServiceRunning(svc)) {
            candidates.push_back(svc);
        }
    }

    if (candidates.empty()) return;

    // 2. Build Dependency Graph
    // We want to stop A before B if A depends on B.
    // EnumDependentServices(B) returns A.
    // So if A is in our candidate list, we record dependency: A -> B (A must stop first).
    
    // However, for standard topological sort (Task Order), we usually say "Do B then A".
    // Here the "Task" is "Stop Service".
    // STOP A (Dependent) -> STOP B (Provider).
    
    // We will perform a sort based on "Depends On".
    // If A depends on B, we must output A first.
    
    // Map service name to node index
    std::map<std::wstring, size_t> nameToIdx;
    for(size_t i=0; i<candidates.size(); ++i) nameToIdx[candidates[i]] = i;

    // Adjacency list: adj[B] contains A (B supports A, so A must stop before B)
    // Actually, let's keep it simple:
    // We want a list sorted such that Dependents appear BEFORE Providers.
    // We can swap if we find a violation.
    
    // Simple Bubble Sort approach (List is tiny, ~4-5 items)
    // If candidates[j] depends on candidates[i], swap them so candidates[j] comes first.
    
    bool changed = true;
    while(changed) {
        changed = false;
        for (size_t i = 0; i < candidates.size(); ++i) {
            ScHandle hSc(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!hSc) break;

            ScHandle hSvc(OpenServiceW(hSc.get(), candidates[i].c_str(), SERVICE_ENUMERATE_DEPENDENTS));
            if (!hSvc) continue;

            // Check if any *later* service depends on this one
            // If candidates[j] (where j > i) depends on candidates[i], then candidates[j] must come FIRST.
            // So we need to move candidates[j] to before candidates[i].
            
            DWORD bytesNeeded = 0;
            DWORD count = 0;
            
            // [FIX] Check return value to resolve C6031. We expect FALSE + ERROR_MORE_DATA.
            if (!EnumDependentServicesW(hSvc.get(), SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count) && 
                GetLastError() != ERROR_MORE_DATA) {
                continue; // Unexpected failure, skip this service
            }
            
            if (bytesNeeded > 0) {
                std::vector<BYTE> buffer(bytesNeeded);
                if (EnumDependentServicesW(hSvc.get(), SERVICE_ACTIVE, 
                    reinterpret_cast<LPENUM_SERVICE_STATUSW>(buffer.data()), 
                    bytesNeeded, &bytesNeeded, &count)) {
                    
                    LPENUM_SERVICE_STATUSW deps = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buffer.data());
                    for (DWORD k=0; k<count; ++k) {
                        std::wstring depName = deps[k].lpServiceName;
                        
                        // Check if this dependent is in our list at a later position
                        for (size_t j = i + 1; j < candidates.size(); ++j) {
                            if (candidates[j] == depName) {
                                // Violation! 'depName' depends on 'candidates[i]', 
                                // so 'depName' must stop BEFORE 'candidates[i]'.
                                // Swap and restart sort
                                std::swap(candidates[i], candidates[j]);
                                changed = true;
                                goto NextPass;
                            }
                        }
                    }
                }
            }
        }
        NextPass:;
    }

    // 3. Execute Suspension in Order
    for (const auto& svc : candidates) {
        Log("[EXECUTOR] Suspending heavy service: " + WideToUtf8(svc.c_str()));
        if (PManContext::Get().subs.serviceMgr && PManContext::Get().subs.serviceMgr->AddService(svc, SERVICE_STOP | SERVICE_QUERY_STATUS)) {
             PManContext::Get().subs.serviceMgr->SuspendService(svc, WindowsServiceManager::BypassMode::Operational);
             s_suspendedServices.push_back(svc);
        }
    }
}

void ServiceWatcher::ResumeSuspendedServices() {
    std::lock_guard<std::mutex> lock(s_suspendMtx);

    if (s_suspendedServices.empty()) return;

    Log("[EXECUTOR] Resuming services...");

    for (const auto& svc : s_suspendedServices) {
        // Resume (Start) the service
        // ServiceManager::ResumeService actually calls StartService
        if (PManContext::Get().subs.serviceMgr) PManContext::Get().subs.serviceMgr->ResumeService(svc);
    }

    s_suspendedServices.clear();
}
