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

#pragma once
#include "types.h"
#include "globals.h"
#include <mutex>
#include <unordered_set>

class ThrottleManager {
public:
    ThrottleManager();
    ~ThrottleManager();

    void Initialize();
    
    // detects a state change (Stable <-> Unstable)
    void OnNetworkStateChange(NetworkState newState);

    // Policy to enroll a process
    void ManageProcess(DWORD pid);

    // Granular Throttle Levels
    enum class ThrottleLevel {
        None,
        Mild,       // Priority: Below Normal, EcoQoS: On
        Aggressive  // Priority: Idle, Hard CPU Cap: 5-10%
    };

    // Executor Integration Point
    void ApplyThrottle(DWORD pid, ThrottleLevel level);

private:
    void UpdateJobLimits(bool enableThrottle);
    void UpdateProcessPriorities(bool enableThrottle);
    
    // Applies strict priority (IDLE) or restores (BELOW_NORMAL)
    void ApplyPriorityToProcess(DWORD pid, bool enableThrottle);

    // Cooldown Logic
    public:
    void TriggerCooldown(DWORD pid); // Called by NetMon when retry storm detected
    
    private:
    bool IsInCooldown(DWORD pid);
    std::unordered_map<DWORD, uint64_t> m_cooldowns; // PID -> Timestamp (end time)

    // [FIX] Per-process Job Objects for granular CPU capping
    // Allows aggressive 5% Hard Cap vs Mild 40% Soft Cap
    std::unordered_map<DWORD, HANDLE> m_processJobs;

    HANDLE m_hJob;
    std::mutex m_mtx;
    std::unordered_set<DWORD> m_managedPids;
    std::unordered_map<DWORD, DWORD> m_originalPriorities; // [FIX] Track original state (Source 1 Invariant)
    bool m_isThrottling;

    void RestoreAll(); // Cleanup helper
};

extern ThrottleManager g_throttleManager;
