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

#include "hands_rl_engine.h"
#include "context.h"
#include "logger.h"
#include "throttle_manager.h"
#include "memory_optimizer.h"
#include "services_watcher.h" // Phase 14
#include "nt_wrapper.h"
#include "tweaks.h" // For privilege separation calls
#include <psapi.h>
#include <algorithm>
#include <shellapi.h> // For SHQueryUserNotificationState

// --------------------------------------------------------------------------
// Process Scout (Phase 11.2)
// --------------------------------------------------------------------------

void ProcessScout::UpdateCache() {
    std::vector<DWORD> pids(4096);
    DWORD bytesReturned;
    
    // Use standard EnumProcesses for the scout loop
    if (!EnumProcesses(pids.data(), sizeof(DWORD) * 4096, &bytesReturned)) {
        return;
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
        
        // [FIX] Phase 1.5: Real Categorization
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
            // Further refinement could check for "ProcessCategory" tweaks or known lists
            snap.category = ProcessCategory::Background_Work;
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
// Executor Implementation (Phase 11.1)
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
    
    // [FIX] Phase 11.5: Watchdog Timer
    m_watchdogRunning = true;
    m_watchdogThread = std::thread(&Executor::WatchdogLoop, this);
}

void Executor::Shutdown() {
    m_watchdogRunning = false;
    if (m_watchdogThread.joinable()) m_watchdogThread.join();
    EmergencyRevertAll();
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

    // 1. Resolve Targets (Phase 11.2)
    TargetSet targets = ResolveTargets(intent.action);

    // 2. Validate (Phase 11.3)
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
        case BrainAction::Suspend_Services:
            success = ApplyServiceSuspension(targets);
            break;
        case BrainAction::Release_Pressure:
            EmergencyRevertAll();
            success = true;
            break;
        default:
            break;
    }

    if (!success) return std::nullopt;

    // 4. Issue Receipt (Phase 16.4)
    Receipt receipt;
    receipt.id = m_nextReceiptId++;
    receipt.action = intent.action;
    receipt.affectedTargets = targets.targets;
    receipt.timestamp = GetTickCount64();

    m_activeReceipts[receipt.id] = receipt;
    return receipt;
}

// Phase 11.2: Targeting Logic
TargetSet Executor::ResolveTargets(BrainAction action) {
    TargetSet result;
    result.snapshotTime = GetTickCount64();
    
    // Fetch snapshot from Scout
    // In Phase 11.2, this reads the cache.
    // For safety, we trigger an update if the cache is stale (not implemented here for brevity).
    m_scout->UpdateCache(); 
    auto snapshot = m_scout->GetSnapshot();

    for (const auto& snap : snapshot) {
        // Filter Logic (Roadmap Phase 11.2)
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

// Phase 11.3: Defense in Depth (Veto Layer)
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

        // [FIX] Affinity Mask 0 Validation (Roadmap 6 Enhancement)
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

// Phase 3.4: Privilege Separation Implementation
bool Executor::ApplyTestProfile(DWORD pid, TestType type, int param) {
    // This runs in the "Executor" context (Elevated/Service), 
    // accepting requests from "Brain" (User Logic).
    
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
    // Phase 13 Integration
    std::vector<DWORD> pids;
    for (const auto& t : targets.targets) pids.push_back(t.pid);

    auto& mem = PManContext::Get().subs.mem;
    if (mem) {
        // Access via Friend or Public API? 
        // We added PerformSmartTrim in Phase 13.
        // We cast to access the new method if it's not in the unique_ptr type yet (it is).
        mem->PerformSmartTrim(pids, aggressive ? MemoryOptimizer::TrimIntensity::Hard : MemoryOptimizer::TrimIntensity::Gentle);
    }
    return true;
}

bool Executor::ApplyServiceSuspension(const TargetSet& /*targets*/) {
    // Phase 14: Service Muscles
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
    if (receipt.action == BrainAction::Throttle_Mild || receipt.action == BrainAction::Throttle_Aggressive) {
        for (const auto& target : receipt.affectedTargets) {
            g_throttleManager.ApplyThrottle(target.pid, ThrottleManager::ThrottleLevel::None);
        }
    }
    else if (receipt.action == BrainAction::Suspend_Services) {
        // Phase 14.3: Auto-Resume
        ServiceWatcher::ResumeSuspendedServices();
    }
    // Memory trim cannot be reverted (it's destructive), which is fine.
    
    return true;
}

// Phase 16.5: Feedback Loop (Implementation)
void Executor::SubmitActionResult(ActionResult result) {
    std::lock_guard<std::mutex> lock(m_stateMtx);
    
    // In a distributed architecture (Service vs User), this would be 
    // where the Service processes the result of an async operation.
    // For now, we simply log the outcome for telemetry.
    
    if (!result.success) {
        Log("Executor: Action Failed! Error=" + std::to_string(result.win32Error));
        
        // Phase 16.2: Penalty Injection
        // If we were fully connected via IPC, we would send a negative reward 
        // back to the Brain here.
    } else {
        // Log("Executor: Action Success. CPU=" + std::to_string(result.actualCpuAfter));
    }
}

void Executor::Heartbeat(uint64_t /*brainTimestamp*/) {
    m_lastBrainHeartbeat = GetTickCount64();
    // Watchdog logic would go here to auto-revert if heartbeat stops
}
