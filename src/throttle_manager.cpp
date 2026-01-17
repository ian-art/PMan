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

#include "throttle_manager.h"
#include "logger.h"
#include "utils.h"
#include "tweaks.h"

ThrottleManager g_throttleManager;

// Cooldown Duration: 60 Seconds
static const uint64_t COOLDOWN_MS = 60000;

ThrottleManager::ThrottleManager() : m_hJob(nullptr), m_isThrottling(false) {}

ThrottleManager::~ThrottleManager() {
    // [FIX] Ensure system state is restored on shutdown (Source 9)
    RestoreAll();
    
    if (m_hJob) {
        // Ensure limits are explicitly cleared before closing handle
        UpdateJobLimits(false); 
        CloseHandle(m_hJob);
    }
}

void ThrottleManager::Initialize() {
    // Create an anonymous Job Object
    m_hJob = CreateJobObject(nullptr, nullptr);
    if (!m_hJob) {
        Log("[THROTTLE] Failed to create Job Object. Adaptive Background Throttling is unavailable. Error: " + std::to_string(GetLastError()));
        return;
    }

    // NOTE: A fresh Job Object starts with no limits (UNTHROTTLED).
    // We do NOT call UpdateJobLimits(false) here to avoid "Invalid Parameter" errors 
    // from trying to disable limits that aren't set yet.
    
    Log("[THROTTLE] Throttle Manager initialized (Job Object Created)");
}

void ThrottleManager::OnNetworkStateChange(NetworkState newState) {
    std::lock_guard lock(m_mtx);
    
    // Strategy: Throttling is ACTIVE only when Network is UNSTABLE.
    bool shouldThrottle = (newState == NetworkState::Unstable);

    if (m_isThrottling != shouldThrottle) {
        // [PERF FIX] Hysteresis: Prevent flapping on jittery connections
        // Wait at least 10 seconds before toggling state
        static uint64_t lastToggleTime = 0;
        uint64_t now = GetTickCount64();
        
        if (now - lastToggleTime < 10000) {
            return; // Ignore rapid changes
        }
        
        m_isThrottling = shouldThrottle;
        lastToggleTime = now;
        
        Log(std::string("[THROTTLE] Global Throttling ") + (m_isThrottling ? "ENGAGED" : "DISENGAGED"));

        // 1. Update Job Object Hard Limits (CPU Rate)
        UpdateJobLimits(m_isThrottling);

        // 2. Update Priorities (IDLE vs NORMAL)
        UpdateProcessPriorities(m_isThrottling);
    }
}

void ThrottleManager::TriggerCooldown(DWORD pid) {
    std::lock_guard lock(m_mtx);
    uint64_t now = GetTickCount64();

    // Fix: Periodic cleanup of expired cooldowns to prevent map bloat
    static uint64_t lastCleanup = 0;
    if (now - lastCleanup > 300000) { // Every 5 mins
        for (auto it = m_cooldowns.begin(); it != m_cooldowns.end(); ) {
            if (now > it->second) it = m_cooldowns.erase(it);
            else ++it;
        }
        lastCleanup = now;
    }
    
    // Set or refresh cooldown
    m_cooldowns[pid] = now + COOLDOWN_MS;
    
    // Force throttle immediately
    ApplyPriorityToProcess(pid, true);
    
    Log("[THROTTLE] Retry Storm Detected! PID " + std::to_string(pid) + " placed in 60s cooldown.");
}

bool ThrottleManager::IsInCooldown(DWORD pid) {
    auto it = m_cooldowns.find(pid);
    if (it == m_cooldowns.end()) return false;
    
    if (GetTickCount64() > it->second) {
        m_cooldowns.erase(it); // Expired
        return false;
    }
    return true;
}

void ThrottleManager::ManageProcess(DWORD pid) {
    if (!m_hJob) return;

    std::lock_guard lock(m_mtx);
    
    // Add to set if new
    if (m_managedPids.find(pid) == m_managedPids.end()) {
        m_managedPids.insert(pid);
        
        // [FIX] Capture Original Priority (Source 1 Invariant: "Failure must always revert")
        HANDLE hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hQuery) {
            DWORD pri = GetPriorityClass(hQuery);
            if (pri != 0) {
                m_originalPriorities[pid] = pri;
            }
            CloseHandle(hQuery);
        }

        // 1. Permanently assign to Job Object (Cannot be removed, only limits changed)
        HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            if (!AssignProcessToJobObject(m_hJob, hProc)) {
                // Common error: Process already in a job.
                // We silently fail here because we can still manage it via Priority API.
            }
            CloseHandle(hProc);
        }

        // 2. Apply immediate priority based on current state
        ApplyPriorityToProcess(pid, m_isThrottling);
    }
}

void ThrottleManager::UpdateJobLimits(bool enableThrottle) {
    if (!m_hJob) return;

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRate = {0};
    
    if (enableThrottle) {
        // SAFETY CHANGE: Removed Hard Cap. Set Soft Cap to 25%.
        // We rely on IDLE_PRIORITY_CLASS (applied elsewhere) for main throttling.
        // [FIX] Disable CPU Rate Control to prevent freezing foreground apps (e.g. YouTube) during network spikes
        cpuRate.ControlFlags = 0; 
        cpuRate.CpuRate = 0; 
    } else {
        // UNCAP: Disable rate control logic entirely
        cpuRate.ControlFlags = 0; 
    }

    if (!SetInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuRate, sizeof(cpuRate))) {
        DWORD err = GetLastError();
        // Ignore "Invalid Parameter" if we are trying to disable something already disabled
        if (err != ERROR_INVALID_PARAMETER || enableThrottle) {
             Log("[THROTTLE] Failed to update Job Limits. Error: " + std::to_string(err));
        }
    }
}

void ThrottleManager::UpdateProcessPriorities(bool enableThrottle) {
    // [FIX] Cache Foreground PID to prevent throttling the active user app (Game/Browser)
    HWND hFg = GetForegroundWindow();
    DWORD fgPid = 0;
    if (hFg) GetWindowThreadProcessId(hFg, &fgPid);

    // Iterate safe copy or handle stale PIDs during iteration
    auto it = m_managedPids.begin();
    while (it != m_managedPids.end()) {
        DWORD pid = *it;

        // [FIX] CRITICAL: Never throttle the foreground application, even if network is unstable.
        // This ensures the user's active game or stream is not interrupted by background logic.
        if (pid == fgPid && fgPid != 0) {
            ++it;
            continue;
        }

        // VERIFY: Check if process is still alive before managing
        DWORD exitCode = 0;
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hCheck || !GetExitCodeProcess(hCheck, &exitCode) || exitCode != STILL_ACTIVE) {
            if (hCheck) CloseHandle(hCheck);
            it = m_managedPids.erase(it); // Remove dead PID
            continue;
        }
        CloseHandle(hCheck);
        
        // If in cooldown, FORCE throttle regardless of global switch
        bool specificThrottle = enableThrottle || IsInCooldown(pid);
        
        ApplyPriorityToProcess(pid, specificThrottle);
        ++it;
    }
}

void ThrottleManager::ApplyPriorityToProcess(DWORD pid, bool enableThrottle) {
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProc) return;

    if (enableThrottle) {
        // ENGAGE: Background Mode
        SetPriorityClass(hProc, IDLE_PRIORITY_CLASS);
        
        // Set I/O Priority to Very Low (0)
        SetProcessIoPriority(pid, 0); 
    } else {
        // DISENGAGE: Restore to Original Priority (Compliance: Source 1)
        DWORD restorePri = BELOW_NORMAL_PRIORITY_CLASS; // Default fallback
        
        // Check if we captured a valid original priority
        std::lock_guard lock(m_mtx);
        auto it = m_originalPriorities.find(pid);
        if (it != m_originalPriorities.end()) {
            restorePri = it->second;
        }

        SetPriorityClass(hProc, restorePri);
        
        // Restore I/O Priority to Normal (2) - Standard default
        SetProcessIoPriority(pid, 2);
    }

    CloseHandle(hProc);
}

void ThrottleManager::RestoreAll() {
    std::lock_guard lock(m_mtx);
    for (DWORD pid : m_managedPids) {
        HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
        if (hProc) {
            DWORD restorePri = BELOW_NORMAL_PRIORITY_CLASS;
            if (m_originalPriorities.count(pid)) {
                restorePri = m_originalPriorities[pid];
            }
            SetPriorityClass(hProc, restorePri);
            SetProcessIoPriority(pid, 2);
            CloseHandle(hProc);
        }
    }
    m_managedPids.clear();
    m_originalPriorities.clear();
    Log("[THROTTLE] Restored all managed processes to original state.");
}
