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

#ifndef PMAN_DECISION_ARBITER_H
#define PMAN_DECISION_ARBITER_H

#include "types.h"
#include "confidence_tracker.h"
#include <unordered_map>
#include <unordered_set> // [FIX] Required for policyAllowedActions

class DecisionArbiter {
public:
    // Public API
    // Single Responsibility: Select exactly one outcome per cycle.
    // Deterministic, Auditable, Safe.
    // [FIX] Added policyAllowedActions to handle "Active Ready State" (Stability Disabled)
    ArbiterDecision Decide(const GovernorDecision& govDecision, const ConsequenceResult& consequence, const ConfidenceMetrics& confidence, const std::unordered_set<int>& policyAllowedActions);

    // Reset internal cooldown states (e.g., on configuration reload)
    void Reset();

    // [FIX] Public Config Setter
    void SetConfidenceThresholds(double cpuVar, double thermVar, double latVar);

private:
    // Anti-oscillation state
    // Maps BrainAction -> Last Execution Timestamp (GetTickCount64)
    std::unordered_map<BrainAction, uint64_t> m_cooldowns;

    // Hard Rules
    bool CheckHardRejection(const GovernorDecision& gov, const ConsequenceResult& seq, DecisionReason& outReason);
    bool CheckCooldown(BrainAction action, DecisionReason& outReason);
    
    // Mapping Logic: Translates Abstract Governor Intent -> Specific Executor Action
    BrainAction MapIntentToAction(const GovernorDecision& gov);

    // Constants
    static constexpr uint64_t ACTION_COOLDOWN_MS = 5000; // 5 seconds minimum between identical heavy actions

    private:
    double m_maxCpuVariance = 25.0;
    double m_maxThermVariance = 5.0;
    double m_maxLatVariance = 50.0;
};

#endif // PMAN_DECISION_ARBITER_H
