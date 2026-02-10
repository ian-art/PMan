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

#include "executor.h"
#include "context.h"
#include "logger.h"
#include "throttle_manager.h"
#include "memory_optimizer.h"
#include "services_watcher.h"
#include "nt_wrapper.h"
#include "tweaks.h" // For privilege separation calls
#include "security_utils.h" // [PHASE 3] The Watchtower
#include <psapi.h>
#include <algorithm>
#include <shellapi.h> // For SHQueryUserNotificationState
#include <wct.h>      // Wait Chain Traversal
#pragma comment(lib, "advapi32.lib")

// [DCM] Universal Security Product Detection (Heuristic)
// We define a local compatible struct to check Process Protection Level (PPL)
// This allows identifying Defender, McAfee, CrowdStrike, etc. without hardcoded names.
typedef struct _PROCESS_PROTECTION_LEVEL_INFORMATION_COMPAT {
    DWORD ProtectionLevel;
} PROCESS_PROTECTION_LEVEL_INFORMATION_COMPAT;

static bool IsProtectedProcess(DWORD pid) {
    if (pid <= 4) return true; 

    // Heuristic 1: If we can't open it for Limited Info, it's likely a protected Anti-Malware service
    UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProcess) {
        return (GetLastError() == ERROR_ACCESS_DENIED);
    }

    // Heuristic 2: Check standard Windows Protection Level
    PROCESS_PROTECTION_LEVEL_INFORMATION_COMPAT ppl = {0};
    // ProcessProtectionLevelInfo = 11
    if (GetProcessInformation(hProcess.get(), (PROCESS_INFORMATION_CLASS)11, &ppl, sizeof(ppl))) {
        // ProtectionLevel > 0 means it is a Signed/Protected System or Antimalware process
        return (ppl.ProtectionLevel != 0);
    }
    return false;
}

// [DCM] Foreground Shielding Implementation
// Boosts the foreground window's Priority and IO Priority to "Shield" it from background AV scans.
static bool ApplyForegroundShield_Impl(DWORD pid) {
    if (pid <= 4) return false;
    
    // Safety: Never boost a Protected Process (AV) even if it steals focus
    if (IsProtectedProcess(pid)) return false;

    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProc) {
        // 1. Boost CPU Priority (Transient)
        SetPriorityClass(hProc, ABOVE_NORMAL_PRIORITY_CLASS);
        
        // 2. Boost IO Priority (Critical for contending with AV Scans)
        // FIX: Explicit cast required for strict C++ enum conversion
        IO_PRIORITY_HINT ioPri = (IO_PRIORITY_HINT)IoPriorityHigh;
        NtWrapper::SetInformationProcess(hProc, ProcessIoPriority, &ioPri, sizeof(ioPri));
        
        CloseHandle(hProc);
        return true;
    }
    return false;
}

// --------------------------------------------------------------------------
// Process Enumeration and Classification Logic
// --------------------------------------------------------------------------

void ProcessScout::UpdateCache() {
    // [FIX] Dynamic Process Enumeration: Loop and resize to handle >4096 processes
    std::vector<DWORD> pids(4096);
    DWORD bytesReturned = 0;
    
    while (true) {
        if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &bytesReturned)) {
            Log("[EXECUTOR] EnumProcesses failed.");
            return;
        }

        // Check for truncation: If buffer is completely full, it might be truncated.
        if (bytesReturned == pids.size() * sizeof(DWORD)) {
            pids.resize(pids.size() * 2);
            continue;
        }
        break;
    }

    DWORD count = bytesReturned / sizeof(DWORD);
    std::vector<Snapshot> newCache;
    newCache.reserve(count);

    uint64_t now = GetTickCount64();

    for (size_t i = 0; i < count; i++) {
        DWORD pid = pids[i];
        if (pid == 0 || pid == 4) continue;

        Snapshot snap;
        snap.identity = { pid, {0, 0} }; 
        snap.timestamp = now;
        
        // Heuristic categorization of processes based on session and window state
        HWND hFg = GetForegroundWindow();
        DWORD fgPid = 0;
        GetWindowThreadProcessId(hFg, &fgPid);
        
        DWORD sessionId = 0;
        ProcessIdToSessionId(pid, &sessionId);

        if (pid == fgPid) {
            snap.category = ProcessCategory::Interactive_Game; // Assumed game/active app
        } else if (sessionId == 0) {
            snap.category = ProcessCategory::System_Critical; // Session 0 Service
        } else {
            // [PHASE 3] The Watchtower: Check for Proxy Launches
            if (SecurityUtils::IsProxyLaunch(pid)) {
                snap.category = ProcessCategory::Suspicious;
                Log("[WATCHTOWER] Detected Proxy Launch on PID " + std::to_string(pid) + ". Tagging as SUSPICIOUS.");
            } else {
                snap.category = ProcessCategory::Background_Work;
            }
        }
        
        newCache.push_back(snap);
    }

    std::unique_lock<std::shared_mutex> lock(m_cacheMtx);
    m_cache = std::move(newCache);
}

std::vector<ProcessScout::Snapshot> ProcessScout::GetSnapshot() const {
    std::shared_lock<std::shared_mutex> lock(m_cacheMtx);
    return m_cache;
}

// --------------------------------------------------------------------------
// Core Action Execution Logic
// --------------------------------------------------------------------------

Executor& Executor::Get() {
    // Rely on PManContext for ownership, but expose singleton accessor
    static Executor* instance = PManContext::Get().subs.executor.get();
    return *instance;
}

Executor::Executor() : m_scout(std::make_unique<ProcessScout>()) {}
Executor::~Executor() { Shutdown(); }

void Executor::Initialize() {
    Log("Executor: Initializing Nervous System...");
    
    // Initialize the safety monitoring thread
    m_watchdogRunning = true;
    m_watchdogThread = std::thread(&Executor::WatchdogLoop, this);

    // Initialize Wait Chain Traversal (Sync Mode)
    // This gives us a handle to query the Kernel Dispatcher directly.
    m_hWctSession = OpenThreadWaitChainSession(0, NULL);
}

void Executor::Shutdown() {
    m_watchdogRunning = false;
    if (m_watchdogThread.joinable()) m_watchdogThread.join();
    EmergencyRevertAll();

    if (m_hWctSession) {
        CloseThreadWaitChainSession(m_hWctSession);
        m_hWctSession = nullptr;
    }
}

void Executor::WatchdogLoop() {
    while (m_watchdogRunning) {
        Sleep(1000);
        uint64_t last = m_lastBrainHeartbeat.load();
        if (last > 0) {
            uint64_t diff = GetTickCount64() - last;
            if (diff > 15000) { // 15 Seconds
                Log("[WATCHDOG] Brain heartbeat lost (>15s). Triggering EMERGENCY REVERT.");
                EmergencyRevertAll();
                m_lastBrainHeartbeat = 0; // Reset to avoid loop
            }
        }
    }
}

std::optional<Executor::Receipt> Executor::Execute(const ActionIntent& intent) {
    std::lock_guard<std::mutex> lock(m_stateMtx);

    // 1. Identify specific processes to target
    TargetSet targets = ResolveTargets(intent.action);

    // 2. Perform safety validation on targets
    if (!HardValidate(intent, targets)) {
        Log("Executor: Intent VETOED by HardValidate.");
        return std::nullopt;
    }

    // 3. Dispatch to Muscles
    bool success = false;
    switch (intent.action) {
        case BrainAction::Throttle_Mild:
            success = ApplyThrottle(targets, false);
            break;
        case BrainAction::Throttle_Aggressive:
            success = ApplyThrottle(targets, true);
            break;
        case BrainAction::Optimize_Memory:
            success = ApplyMemoryTrim(targets, true); // Hard trim
            break;
        case BrainAction::Optimize_Memory_Gentle:
            success = ApplyMemoryTrim(targets, false); // Gentle trim (skips <100MB)
            break;
        case BrainAction::Suspend_Services:
            // [ARCH-FIX] Safety: targets are ignored. We only suspend the static AllowedList.
            success = ApplyServiceSuspension(targets);
            break;
        case BrainAction::Release_Pressure:
            EmergencyRevertAll();
            success = true;
            break;
        case BrainAction::Probation:
            // [PHASE 3] The Probation Officer
            // Force: BELOW_NORMAL_PRIORITY_CLASS + Trim Memory
            success = ApplyThrottle(targets, true); // Aggressive Throttle (Low/Idle Priority)
            success &= ApplyMemoryTrim(targets, true); // Hard Trim
            break;

        case BrainAction::Shield_Foreground:
            // [DCM] Universal Foreground Shielding
            // Triggered when "Universal AV Awareness" detects background pressure.
            {
                DWORD fgPid = 0;
                DWORD fgTid = GetWindowThreadProcessId(GetForegroundWindow(), &fgPid);
                
                // Clear targets to ensure we only track what we actually touch here
                targets.targets.clear();

                // [WCT] Anti-Deadlock: Check if the foreground thread is blocked by a background process
                // Any dependency found (e.g. Audiodg.exe) is boosted and added to 'targets' for later Revert.
                ResolveDependencies(fgTid, targets.targets);

                if (fgPid > 4 && ApplyForegroundShield_Impl(fgPid)) {
                    // Add the main foreground window
                    targets.targets.push_back({fgPid, {0, 0}});
                    success = true;
                } else if (!targets.targets.empty()) {
                    // We successfully boosted a dependency even if the foreground app failed/was protected
                    success = true;
                }
            }
            break;
    }

    if (!success) return std::nullopt;

    // 4. Generate a transaction record for potential rollback
    Receipt receipt;
    receipt.id = m_nextReceiptId++;
    receipt.action = intent.action;
    receipt.affectedTargets = targets.targets;
    receipt.timestamp = GetTickCount64();

    m_activeReceipts[receipt.id] = receipt;
    return receipt;
}

// Logic to translate abstract intents into concrete process lists
TargetSet Executor::ResolveTargets(BrainAction action) {
    TargetSet result;
    result.snapshotTime = GetTickCount64();
    
    // Fetch snapshot from Scout
    // Criteria to select background work while excluding interactive apps
    // For safety, we trigger an update if the cache is stale (not implemented here for brevity).
    m_scout->UpdateCache(); 
    auto snapshot = m_scout->GetSnapshot();

    for (const auto& snap : snapshot) {
        // Filter Logic
        // Target = (Category == Background_Work)
        // Exclude = (Category == Interactive_Game || System_Critical || Interactive_Desktop)
        
        bool isTarget = false;

        // Logic: Only target background work for Throttling
        if (action == BrainAction::Throttle_Mild || action == BrainAction::Throttle_Aggressive) {
            // Need robust classification here. 
            // For this patch, we rely on the Scout's classification.
            if (snap.category == ProcessCategory::Background_Work) {
                isTarget = true;
            }
        }
        else if (action == BrainAction::Optimize_Memory) {
             // Memory optimization targets almost everything except games
             if (snap.category != ProcessCategory::Interactive_Game && 
                 snap.category != ProcessCategory::System_Critical) {
                 isTarget = true;
             }
        }

        if (isTarget) {
            result.targets.push_back(snap.identity);
        }
    }
    
    return result;
}

// Hard-coded safety rules to prevent system instability
bool Executor::HardValidate(const ActionIntent& intent, const TargetSet& targets) {
    // Rule 1: External Governor (Game Mode) Check
    // ... (Existing Game Mode check) ...

    // Rule 2: Critical Process & Session 0 Isolation
    for (const auto& target : targets.targets) {
        if (target.pid <= 4) return false;
        if (target.pid == GetCurrentProcessId()) return false;

        // [FIX] Explicit Session 0 Check
        DWORD sessionId = 0;
        if (ProcessIdToSessionId(target.pid, &sessionId) && sessionId == 0) {
            if (intent.action == BrainAction::Throttle_Aggressive) return false;
        }

        // [DCM] Universal AV Safety: Never Throttling/Trimming Protected Processes
        // This ensures we never accidentally fight with Defender, McAfee, etc.
        if (IsProtectedProcess(target.pid)) {
             Log("[SEC] VETO: Attempted to touch Protected/AV Process PID " + std::to_string(target.pid));
             return false;
        }

        // [FIX] Validates process state to avoid touching zombies or locked threads
        // Prevent touching processes with invalid or locked affinity states
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid);
        if (hCheck) {
            DWORD_PTR procMask = 0;
            DWORD_PTR sysMask = 0;
            if (GetProcessAffinityMask(hCheck, &procMask, &sysMask)) {
                // If mask is 0, the process is in a zombie/invalid state.
                // We must NOT attempt to manage it.
                if (procMask == 0) {
                    CloseHandle(hCheck);
                    return false; 
                }
            }
            CloseHandle(hCheck);
        }
    }

    return true;
}

// Implementation of isolated experimental parameters
bool Executor::ApplyTestProfile(DWORD pid, TestType type, int param) {
    // This runs in the "Executor" context (Elevated/Service).
    // [ARCH-FIX] SAFETY WARNING: This bypasses the Deterministic Controller.
    // It should ONLY be used for manual debugging or strictly controlled calibration,
    // never for automated RL "exploration" in a production environment.
    
    // Safety check on PID?
    if (pid <= 4 || pid == GetCurrentProcessId()) return false;

    switch (type) {
        case TestType::IoPriority:
             // param: 0=VeryLow, 1=Low, 2=Normal
             SetProcessIoPriority(pid, param); 
             return true;
        case TestType::CorePinning:
             // param: 1=Hybrid, 2=P-Core
             if (param == 1) SetHybridCoreAffinity(pid, 1);
             else if (param == 2) SetProcessAffinity(pid, 2);
             return true;
        case TestType::MemoryCompression:
             // param: 1=Compress, 2=Empty
             SetMemoryCompression(param);
             return true;
    }
    return false;
}

// --------------------------------------------------------------------------
// Muscles Integration
// --------------------------------------------------------------------------

bool Executor::ApplyThrottle(const TargetSet& targets, bool aggressive) {
    ThrottleManager::ThrottleLevel level = aggressive ? 
        ThrottleManager::ThrottleLevel::Aggressive : 
        ThrottleManager::ThrottleLevel::Mild;

    for (const auto& target : targets.targets) {
        g_throttleManager.ApplyThrottle(target.pid, level);
    }
    return true;
}

bool Executor::ApplyMemoryTrim(const TargetSet& targets, bool aggressive) {
    // Integration with the Memory Optimizer subsystem
    std::vector<DWORD> pids;
    for (const auto& t : targets.targets) pids.push_back(t.pid);

    auto& mem = PManContext::Get().subs.mem;
    if (mem) {
        // Access via Friend or Public API? 
        // We added PerformSmartTrim
        // We cast to access the new method if it's not in the unique_ptr type yet (it is).
        mem->PerformSmartTrim(pids, aggressive ? MemoryOptimizer::TrimIntensity::Hard : MemoryOptimizer::TrimIntensity::Gentle);
    }
    return true;
}

bool Executor::ApplyServiceSuspension(const TargetSet& /*targets*/) {
    // Logic for suspending non-essential services
    // Note: We ignore the 'targets' list because Service Suspension is a global policy 
    // defined by the AllowedList in ServiceWatcher. We don't target arbitrary services.
    ServiceWatcher::SuspendAllowedServices();
    return true; 
}

void Executor::EmergencyRevertAll() {
    std::lock_guard<std::mutex> lock(m_stateMtx);
    
    Log("Executor: Emergency Revert Triggered!");

    // 1. Revert Throttling
    // Iterate all tracked receipts and undo
    for (auto it = m_activeReceipts.rbegin(); it != m_activeReceipts.rend(); ++it) {
        Revert(it->second);
    }
    m_activeReceipts.clear();
}

bool Executor::Revert(const Receipt& receipt) {
    // Undo logic based on action type
    if (receipt.action == BrainAction::Throttle_Mild || receipt.action == BrainAction::Throttle_Aggressive || receipt.action == BrainAction::Probation) {
        for (const auto& target : receipt.affectedTargets) {
            g_throttleManager.ApplyThrottle(target.pid, ThrottleManager::ThrottleLevel::None);
        }
    }
    else if (receipt.action == BrainAction::Suspend_Services) {
        // Automatically resumes previously suspended services
        ServiceWatcher::ResumeSuspendedServices();
    }
    else if (receipt.action == BrainAction::Shield_Foreground) {
        // [DCM] Revert Foreground Shielding (Restore Normal Priority)
        for (const auto& target : receipt.affectedTargets) {
            HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, target.pid);
            if (hProc) {
                SetPriorityClass(hProc, NORMAL_PRIORITY_CLASS);
                
                // FIX: Explicit cast required for strict C++ enum conversion
                IO_PRIORITY_HINT ioPri = (IO_PRIORITY_HINT)IoPriorityNormal;
                NtWrapper::SetInformationProcess(hProc, ProcessIoPriority, &ioPri, sizeof(ioPri));
                CloseHandle(hProc);
            }
        }
    }
    // Memory trim cannot be reverted (it's destructive), which is fine.
    
    return true;
}

// Logic for processing and logging action outcomes
void Executor::SubmitActionResult(ActionResult result) {
    std::lock_guard<std::mutex> lock(m_stateMtx);
    
    // In a distributed architecture (Service vs User), this would be 
    // where the Service processes the result of an async operation.
    // For now, we simply log the outcome for telemetry.
    
    if (!result.success) {
        Log("Executor: Action Failed! Error=" + std::to_string(result.win32Error));
        
        // Calculates negative reinforcement for failed actions
        // If we were fully connected via IPC, we would send a negative reward 
        // back to the Brain here.
    } else {
        // Log("Executor: Action Success. CPU=" + std::to_string(result.actualCpuAfter));
    }
}

void Executor::ResolveDependencies(DWORD rootThreadId, std::vector<ProcessIdentity>& boosted) {
    if (!m_hWctSession || rootThreadId == 0) return;

    WAITCHAIN_NODE_INFO NodeInfoArray[WCT_MAX_NODE_COUNT];
    DWORD NodeCount = WCT_MAX_NODE_COUNT;
    BOOL IsCycle = FALSE;

    // Ask the Kernel: "Who is holding this thread?"
    if (GetThreadWaitChain(m_hWctSession, NULL, 0, rootThreadId, &NodeCount, NodeInfoArray, &IsCycle)) {
        for (DWORD i = 0; i < NodeCount; i++) {
            if (NodeInfoArray[i].ObjectType == WctThreadType) {
                DWORD blockerPid = NodeInfoArray[i].ThreadObject.ProcessId;
                
                // If it's a valid process (not System/Idle)
                if (blockerPid > 4 && blockerPid != GetCurrentProcessId()) {
                    
                    // Apply Shield
                    if (ApplyForegroundShield_Impl(blockerPid)) {
                         Log("[WCT] Anti-Deadlock: Boosted dependency PID " + std::to_string(blockerPid));
                         
                         // Add to list so we can Revert (Unboost) it later
                         boosted.push_back({blockerPid, {0, 0}});
                    }
                }
            }
        }
    }
}

void Executor::Heartbeat(uint64_t /*brainTimestamp*/) {
    m_lastBrainHeartbeat = GetTickCount64();
    // Watchdog logic would go here to auto-revert if heartbeat stops
}
