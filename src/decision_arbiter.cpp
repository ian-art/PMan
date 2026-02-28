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
#include "context.h"
#include "investigator.h"
#include <unordered_set> // [FIX] Required for policyAllowedActions
#include <cmath> // Required for std::isnan

ArbiterDecision DecisionArbiter::Decide(const GovernorDecision& govDecision, const ConsequenceResult& consequence, const ConfidenceMetrics& confidence, const std::unordered_set<int>& policyAllowedActions) {
    ArbiterDecision decision;
    decision.decisionTime = GetTickCount64();

    // Check if "Stability (Inaction)" is disabled in policy
    bool maintainForbidden = (policyAllowedActions.find((int)BrainAction::Maintain) == policyAllowedActions.end());
    
    // 1. Identify Candidate
    BrainAction intentAction = MapIntentToAction(govDecision);

    // [PATCH] Policy Enforcement: Force Active Mode
    // If Maintain is forbidden (User unchecked "Stability"), override Idle with Boost.
    if (intentAction == BrainAction::Maintain && maintainForbidden) {
        intentAction = BrainAction::Boost_Process;
    }

    // [FIX] Hysteresis (Sticky Boost)
    // If we are currently "Maintaining" (Governor sees no pressure), but we successfully
    // boosted recently (within 5s), we sustain the boost to prevent rapid toggling.
    if (intentAction == BrainAction::Maintain) {
        auto it = m_cooldowns.find(BrainAction::Boost_Process);
        if (it != m_cooldowns.end()) {
             // If we boosted less than 5 seconds ago
             if ((decision.decisionTime - it->second) < 5000) {
                 intentAction = BrainAction::Boost_Process;
             }
        }
    }
    
    // 2. Evaluate Constraints
    bool hardReject = false;
    bool confReject = false;
    bool cooldownReject = false;
    DecisionReason rejectReason = DecisionReason::None;

    // A. Hard Rules
    if (!CheckHardRejection(govDecision, consequence, rejectReason)) {
        hardReject = true;
    }
    // B. Confidence Rules
    else if (std::isnan(confidence.cpuVariance) ||
             std::isnan(confidence.thermalVariance) ||
             std::isnan(confidence.latencyVariance) ||
             confidence.cpuVariance > m_maxCpuVariance ||
             confidence.thermalVariance > m_maxThermVariance ||
             confidence.latencyVariance > m_maxLatVariance ||
             consequence.confidence < CONFIDENCE_MIN) {
        
        // [INVESTIGATOR] The System Detective Trigger
        // Before failing closed due to low confidence, summon the Investigator.
        auto& investigator = PManContext::Get().subs.investigator;
        bool investigationResolved = false;

        if (investigator) {
            InvestigationVerdict verdict = investigator->Diagnose(govDecision);
            
            if (verdict.resolved) {
                // If the Investigator cleared the confusion (e.g., Aliasing detected),
                // we override the confidence rejection.
                if (verdict.recommendVeto) {
                    // Recommendation: Do Nothing (False Alarm)
                    // We treat this as "NoActionNeeded" rather than "LowConfidence" failure.
                    decision.selectedAction = BrainAction::Maintain;
                    decision.reason = DecisionReason::NoActionNeeded; // "False Alarm" effectively
                    decision.decisionTime = GetTickCount64();
                    return decision; // Return immediately
                } else {
                    // Recommendation: Proceed (True Pressure Confirmed)
                    investigationResolved = true;
                    // [FIX] Feedback Loop: Immediate Confidence Update
                    if (auto& conf = PManContext::Get().subs.confidence) {
                        conf->ForceConfidence(verdict.confidenceBoost);
                    }
                }
            }
        }

        if (!investigationResolved) {
            confReject = true;
            rejectReason = DecisionReason::LowConfidence;
        }
    }
    // C. Cooldown Rules (Only check if we actually have an intent)
    else if (intentAction != BrainAction::Maintain && !CheckCooldown(intentAction, rejectReason)) {
        cooldownReject = true;
    }

    // 3. Determine Final Selection
    if (hardReject || confReject || cooldownReject) {
        // [LOGIC] Smart Fallback
        // If the primary action failed, check if we can fallback to an Active Ready State
        // instead of doing nothing.
        
        bool fallbackSuccess = false;

        if (maintainForbidden) {
             // Try to fallback to Boost_Process (Low risk active state)
             // But ONLY if it wasn't the action we just rejected.
             if (intentAction != BrainAction::Boost_Process) {
                 // Enforce physical cooldown for fallbacks to prevent Policy rejection spam loops
                     bool fallbackReady = true;
                     auto it = m_cooldowns.find(BrainAction::Boost_Process);
                     if (it != m_cooldowns.end() && (decision.decisionTime - it->second) < ACTION_COOLDOWN_MS) {
                         fallbackReady = false;
                     }
                     
                     if (fallbackReady) {
                         decision.selectedAction = BrainAction::Boost_Process;
                         decision.reason = DecisionReason::Approved; // Fallback Approved
                         m_cooldowns[BrainAction::Boost_Process] = decision.decisionTime;
                         fallbackSuccess = true;
                     }
             }
        }

        if (!fallbackSuccess) {
            // [SAFETY] Hard Physical Limit
            // Even if the user wants "Always Active", if we can't safely boost,
            // we MUST Maintain to prevent damage or instability.
            decision.selectedAction = BrainAction::Maintain;
            decision.reason = rejectReason;
        }
    } else {
        decision.selectedAction = intentAction;
        if (intentAction == BrainAction::Maintain) {
            decision.reason = DecisionReason::NoActionNeeded;
        } else {
            decision.reason = DecisionReason::Approved;
            // Update state
            m_cooldowns[intentAction] = decision.decisionTime;
        }
    }

    // Propagate sensor target PID into the ArbiterDecision for SandboxExecutor.
    // Only attach for memory actions; other actions resolve their own targets via ResolveTargets().
    if (decision.selectedAction == BrainAction::Action_MemoryTrim ||
        decision.selectedAction == BrainAction::Action_MemoryHarden) {
        decision.targetPid = govDecision.targetPid;
    }

    // 4. Generate Counterfactuals (The "Why not?" List)
    // "Which other actions were considered, and exactly why they were rejected."
    for (int i = 0; i < (int)BrainAction::Count; ++i) {
        BrainAction alt = (BrainAction)i;
        
        // Skip the chosen action (it's in the main record)
        if (alt == decision.selectedAction) continue;

        RejectionReason reason;

        if (alt == intentAction) {
            // This was the Governor's choice, but WE rejected it.
            if (hardReject) reason = RejectionReason::PolicyViolation; // Unsafe consequence or gov restriction
            else if (confReject) reason = RejectionReason::LowConfidence;
            else if (cooldownReject) reason = RejectionReason::CooldownActive;
            else reason = RejectionReason::PolicyViolation; // Fallback
        } else {
            // This was NOT the Governor's choice.
            // Why? Because the Governor chose something else (LowerBenefit) 
            // OR because the Governor strictly forbid it (PolicyViolation).
            
            // Check if explicitly forbidden by AllowedActionClass
            bool explicitForbidden = false;
            if (govDecision.allowedActions == AllowedActionClass::None) explicitForbidden = true;
            // (Refinement: Could map BrainAction back to AllowedActionClass to check more granularly, 
            // but for now, if it wasn't the mapped intent, it's LowerBenefit unless global lock).
            
            if (explicitForbidden) reason = RejectionReason::PolicyViolation;
            else reason = RejectionReason::LowerBenefit;
        }

        decision.rejectedAlternatives.push_back({alt, reason});
    }

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
    // [FIX] Traffic Enforcer: Emergency Boosts bypass cooldowns.
    // We want them to sustain continuously if the signal persists.
    if (action == BrainAction::Boost_Process) return true;

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
            // Route through sensor pipeline: only act if Optimizer identified a target.
            // If no target was proposed (targetPid == 0), do nothing to avoid blind trimming.
            if (gov.targetPid != 0) {
                return BrainAction::Action_MemoryTrim;
            }
            return BrainAction::Maintain;

        case AllowedActionClass::MemoryHarden:
            // Route through sensor pipeline: only harden if Optimizer confirmed eligibility.
            if (gov.targetPid != 0) {
                return BrainAction::Action_MemoryHarden;
            }
            return BrainAction::Maintain;

        case AllowedActionClass::ThermalSafety:
            // If thermal pressure is critical, throttle aggressively
            if (gov.dominant == DominantPressure::Thermal) {
                return BrainAction::Throttle_Aggressive;
            }
            return BrainAction::Throttle_Mild;

        case AllowedActionClass::IoPrioritization:
            // [PATCH] Contextual I/O Strategy
            // If User is Active (Interactive Mode), we BOOST the foreground app (Release Pressure).
            // If User is Idle (Sustained/Background), we THROTTLE the hogs (Throttle Mild).
            if (gov.dominant == DominantPressure::Disk) {
                if (gov.mode == SystemMode::Interactive) {
                    return BrainAction::Release_Pressure; // Boost Foreground
                }
                return BrainAction::Throttle_Mild; // Suppress Background
            }
            return BrainAction::Release_Pressure;

        case AllowedActionClass::Scheduling:
            // CPU Contention logic
            if (gov.mode == SystemMode::Interactive) {
                return BrainAction::Release_Pressure; // Ensure responsiveness
            }
            return BrainAction::Optimize_Memory; // Fallback or distinct scheduling action

        case AllowedActionClass::PerformanceBoost:
            return BrainAction::Boost_Process;

        case AllowedActionClass::SecurityMitigation:
            // The Watchtower: Probation
            // This bypasses normal resource checks because it is a security mandate.
            return BrainAction::Probation;

        case AllowedActionClass::None:
        default:
            return BrainAction::Maintain;
    }
}

void DecisionArbiter::Reset() {
    m_cooldowns.clear();
}

void DecisionArbiter::SetConfidenceThresholds(double cpuVar, double thermVar, double latVar) {
    m_maxCpuVariance = cpuVar;
    m_maxThermVariance = thermVar;
    m_maxLatVariance = latVar;
}
