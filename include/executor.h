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
#include <vector>
#include <optional>
#include <mutex>
#include <atomic>
#include <map>
#include <shared_mutex>
#include <unordered_map>

// Phase 11.2: The "Scout" Pattern
// Decoupled process snapshotting to prevent UI blocking
class ProcessScout {
public:
    struct Snapshot {
        ProcessIdentity identity;
        ProcessCategory category;
        uint64_t timestamp;
    };

    void UpdateCache();
    std::vector<Snapshot> GetSnapshot() const;

private:
    mutable std::shared_mutex m_cacheMtx;
    std::vector<Snapshot> m_cache;
};

// Phase 11: The Executor Hub (Nervous System)
class Executor {
    friend class PManContext; // Allow Context to instantiate private constructor

public:
    // Singleton Access (Phase 11.1)
    static Executor& Get();

    void Initialize();
    void Shutdown();

    // Phase 16.4: Receipt for Rollback
    struct Receipt {
        uint64_t id;
        BrainAction action;
        std::vector<ProcessIdentity> affectedTargets;
        uint64_t timestamp;
    };

    // Phase 11.1: Unified Command Interface
    std::optional<Receipt> Execute(const ActionIntent& intent);
    
    // Phase 11.1: Safety Reverts
    bool Revert(const Receipt& receipt);
    void EmergencyRevertAll(); // "Nuclear option"

    // Phase 11.5: Watchdog Timer
    void Heartbeat(uint64_t brainTimestamp);

    // Phase 16.5: Feedback Loop
    void SubmitActionResult(ActionResult result);

    // [FIX] Phase 3.4: Privilege Separation (A/B Testing Interface)
    // Must be PUBLIC to be called by Brain
    enum class TestType { IoPriority, CorePinning, MemoryCompression };
    bool ApplyTestProfile(DWORD pid, TestType type, int param);

    // Destructor must be public for std::unique_ptr
    ~Executor();

private:
    Executor();

    // Phase 11.3: Defense in Depth (Veto Layer)
    bool HardValidate(const ActionIntent& intent, const TargetSet& targets);

    // Phase 11.2: Targeting System
    TargetSet ResolveTargets(BrainAction action);

    // Phase 14.2: Service Safety
    bool IsSafeToSuspend(const std::wstring& serviceName);

    // Phase 11.5: Watchdog State
    std::thread m_watchdogThread;
    std::atomic<bool> m_watchdogRunning{false};
    void WatchdogLoop();

    // Internal "Muscles" (Delegates to Managers)
    bool ApplyThrottle(const TargetSet& targets, bool aggressive);
    bool ApplyMemoryTrim(const TargetSet& targets, bool aggressive);
    bool ApplyServiceSuspension(const TargetSet& targets);

    // Internal Helpers
    void PruneStaleReceipts();

    // State
    std::mutex m_stateMtx;
    std::atomic<uint64_t> m_lastBrainHeartbeat{0};
    std::map<uint64_t, Receipt> m_activeReceipts;
    std::atomic<uint64_t> m_nextReceiptId{1};
    
    std::unique_ptr<ProcessScout> m_scout;
};
