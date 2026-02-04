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

#include "decision_arbiter.h"
#include "utils.h" // For time helpers if needed
#include "constants.h"

ArbiterDecision DecisionArbiter::Decide(const GovernorDecision& govDecision, const ConsequenceResult& consequence, const ConfidenceMetrics& confidence) {
    ArbiterDecision decision;
    decision.decisionTime = GetTickCount64();
    decision.selectedAction = BrainAction::Maintain; // Default to safe inaction
    decision.reason = DecisionReason::None;

    // 1. Hard Rejection Rules (Safety First)
    DecisionReason rejectReason;
    if (!CheckHardRejection(govDecision, consequence, rejectReason)) {
        decision.reason = rejectReason;
        return decision;
    }

    // Confidence-Driven Conservatism (Variance Kill Switch)
    // Rule: High historical variance -> FORCE NoAction
    if (confidence.cpuVariance > MAX_CPU_VARIANCE ||
        confidence.thermalVariance > MAX_THERM_VARIANCE ||
        confidence.latencyVariance > MAX_LAT_VARIANCE) {
        decision.selectedAction = BrainAction::Maintain;
        decision.reason = DecisionReason::LowConfidence;
        return decision;
    }

    // Model Confidence Check (Prediction Specific)
    // Rule: "if (prediction.confidence < CONFIDENCE_MIN) Arbiter must return NoAction"
    if (consequence.confidence < CONFIDENCE_MIN) {
        decision.selectedAction = BrainAction::Maintain;
        decision.reason = DecisionReason::LowConfidence;
        return decision;
    }

    // 2. Map Governor Intent to Specific Action
    BrainAction candidateAction = MapIntentToAction(govDecision);

    // 3. Validation: If mapping resulted in Maintain, we are done
    if (candidateAction == BrainAction::Maintain) {
        decision.selectedAction = BrainAction::Maintain;
        decision.reason = DecisionReason::NoActionNeeded;
        return decision;
    }

    // 4. Cooldown Enforcement (Anti-Oscillation)
    // "No oscillation within a cooldown window"
    if (!CheckCooldown(candidateAction, rejectReason)) {
        decision.selectedAction = BrainAction::Maintain;
        decision.reason = rejectReason;
        return decision;
    }

    // 5. Final Approval
    decision.selectedAction = candidateAction;
    decision.reason = DecisionReason::Approved;

    // Update state for successful action
    m_cooldowns[candidateAction] = decision.decisionTime;

    return decision;
}

bool DecisionArbiter::CheckHardRejection(const GovernorDecision& gov, const ConsequenceResult& seq, DecisionReason& outReason) {
    // Rule: Hard actions require explicit Governor permission
    if (gov.allowedActions == AllowedActionClass::None) {
        outReason = DecisionReason::GovernorRestricted;
        return false;
    }

    // Rule: If all actions have net-negative score -> NoAction
    // (Evaluated by ConsequenceEvaluator returning isSafe = false)
    if (!seq.isSafe) {
        outReason = DecisionReason::ConsequenceUnsafe;
        return false;
    }

    // Rule: Thermal Safety Priority
    if (gov.dominant == DominantPressure::Thermal && gov.allowedActions != AllowedActionClass::ThermalSafety) {
        outReason = DecisionReason::HardRuleViolation;
        return false; // Cannot perform non-cooling actions during thermal event
    }

    return true;
}

bool DecisionArbiter::CheckCooldown(BrainAction action, DecisionReason& outReason) {
    // Stateless except for bounded cooldown timers
    auto it = m_cooldowns.find(action);
    if (it != m_cooldowns.end()) {
        uint64_t now = GetTickCount64();
        if (now < it->second) {
             // Handle time wrap-around or clock skew
             m_cooldowns.erase(it);
             return true;
        }

        if ((now - it->second) < ACTION_COOLDOWN_MS) {
            outReason = DecisionReason::CooldownActive;
            return false;
        }
    }
    return true;
}

BrainAction DecisionArbiter::MapIntentToAction(const GovernorDecision& gov) {
    // Deterministic mapping of Abstract Class -> Concrete BrainAction
    
    switch (gov.allowedActions) {
        case AllowedActionClass::MemoryReclaim:
            // Only optimize memory if strictly allowed
            return BrainAction::Optimize_Memory;

        case AllowedActionClass::ThermalSafety:
            // If thermal pressure is critical, throttle aggressively
            if (gov.dominant == DominantPressure::Thermal) {
                return BrainAction::Throttle_Aggressive;
            }
            return BrainAction::Throttle_Mild;

        case AllowedActionClass::IoPrioritization:
            // "Release Pressure" contextually handles I/O priority boosts in Executor
            // or "Throttle_Mild" if we need to suppress background I/O.
            // Assuming Governor wants to relieve disk pressure:
            if (gov.dominant == DominantPressure::Disk) {
                return BrainAction::Throttle_Mild; // Suppress contention
            }
            return BrainAction::Release_Pressure; // Boost foreground I/O

        case AllowedActionClass::Scheduling:
            // CPU Contention logic
            if (gov.mode == SystemMode::Interactive) {
                return BrainAction::Release_Pressure; // Ensure responsiveness
            }
            return BrainAction::Optimize_Memory; // Fallback or distinct scheduling action

        case AllowedActionClass::None:
        default:
            return BrainAction::Maintain;
    }
}

void DecisionArbiter::Reset() {
    m_cooldowns.clear();
}
