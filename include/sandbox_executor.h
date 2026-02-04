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

#ifndef PMAN_SANDBOX_EXECUTOR_H
#define PMAN_SANDBOX_EXECUTOR_H

#include "types.h"

struct SandboxResult {
    bool executed;
    bool reversible;
    bool committed;
    const char* reason;
    uint64_t cooldownRemaining = 0;
};

class SandboxExecutor {
public:
    // Zero-Risk Authority Gate
    // Executes Reversible Actions (Throttle_Mild) on Self.
    // If approved, COMMITS the action (no rollback).
    SandboxResult TryExecute(ArbiterDecision& decision);

    // Guaranteed State Restoration (Manual override only)
    void Rollback();

    // State Query for Safety Layers
    bool IsLeaseActive() const;

    ~SandboxExecutor();

private:
    bool IsReversible(BrainAction action) const;
    
    // Internal State for Rollback
    bool m_actionApplied = false;
    DWORD m_originalPriorityClass = 0;
    HANDLE m_hTarget = nullptr;

    // Time-Bound Authority Lease
    uint64_t m_leaseStart = 0;
    static constexpr uint64_t MAX_LEASE_MS = 5000; // 5 Seconds Max Duration

    // Authority Cooldown (Rate-of-Change Limiter)
    uint64_t m_lastReleaseTime = 0;
    static constexpr uint64_t COOLDOWN_MS = 10000; // 10 Seconds
};

#endif // PMAN_SANDBOX_EXECUTOR_H
