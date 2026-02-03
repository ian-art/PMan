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

// Decoupled process snapshotting system to prevent UI blocking
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

// Central subsystem for executing and managing system interventions
class Executor {
    friend class PManContext; // Allow Context to instantiate private constructor

public:
    // Thread-safe singleton accessor
    static Executor& Get();

    void Initialize();
    void Shutdown();

    // Structure tracking executed actions for potential reversion
    struct Receipt {
        uint64_t id;
        BrainAction action;
        std::vector<ProcessIdentity> affectedTargets;
        uint64_t timestamp;
    };

    // Main entry point for dispatching corrective actions
    std::optional<Receipt> Execute(const ActionIntent& intent);
    
    // Reverts a specific action based on its transaction receipt
    bool Revert(const Receipt& receipt);
    void EmergencyRevertAll(); // "Nuclear option"

    // Monitoring system to ensure the decision engine is active
    void Heartbeat(uint64_t brainTimestamp);

    // Reports the outcome of an action back to the optimization engine
    void SubmitActionResult(ActionResult result);

    // Secure interface for isolating experimental parameter tests
    // Must be PUBLIC to be called by Brain
    enum class TestType { IoPriority, CorePinning, MemoryCompression };
    bool ApplyTestProfile(DWORD pid, TestType type, int param);

    // Destructor must be public for std::unique_ptr
    ~Executor();

private:
    Executor();

    // Final safety check preventing dangerous actions before execution
    bool HardValidate(const ActionIntent& intent, const TargetSet& targets);

    // Identifies specific process IDs matching the abstract action intent
    TargetSet ResolveTargets(BrainAction action);

    // Checks if a service is on the safe-to-suspend allowlist
    bool IsSafeToSuspend(const std::wstring& serviceName);

    // // State variables for the keep-alive monitor
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
