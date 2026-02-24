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

#include "autonomous_engine.h"
#include "context.h"
#include "logger.h"
#include "globals.h"
#include "governor.h"
#include "consequence_evaluator.h"
#include "decision_arbiter.h"
#include "shadow_executor.h"
#include "reality_sampler.h"
#include "prediction_ledger.h"
#include "confidence_tracker.h"
#include "sandbox_executor.h"
#include "intent_tracker.h"
#include "outcome_guard.h"
#include "authority_budget.h"
#include "provenance_ledger.h"
#include "policy_contract.h"
#include "external_verdict.h"
#include "policy_optimizer.h"
#include "predictive_model.h"
#include "telemetry_agent.h"
#include "tray_animator.h"
#include <algorithm>

// ---------------------------------------------------------------------------
// AutonomousEngine::CaptureSnapshot
// [OPTIMIZED] Non-blocking read from background telemetry agent
// Offloads PDH and GetSystemTimes to worker thread
// Mirrors the original file-static CaptureSnapshot() that lived in main.cpp.
// ---------------------------------------------------------------------------
SystemSignalSnapshot AutonomousEngine::CaptureSnapshot() const
{
    if (auto& agent = PManContext::Get().subs.telemetry) {
        return agent->GetLatestSnapshot();
    }
    return {}; // Safety fallback
}

// ---------------------------------------------------------------------------
// AutonomousEngine::Init
// Called once during subsystem initialization in RunPMan(), after all
// dependencies are ready.
// ---------------------------------------------------------------------------
void AutonomousEngine::Init()
{
    Log("[AUTONOMOUS_ENGINE] Initialized.");
}

// ---------------------------------------------------------------------------
// AutonomousEngine::Shutdown
// Called during teardown after WorkerQueue::Stop() has returned, so no
// Tick() call can be in flight at this point.
// ---------------------------------------------------------------------------
void AutonomousEngine::Shutdown()
{
    Log("[AUTONOMOUS_ENGINE] Shutdown.");
}

// ---------------------------------------------------------------------------
// AutonomousEngine::Tick
// Full SENSE->THINK->AUTHORIZE->ACT->LEARN cycle.
// Body moved verbatim from RunAutonomousCycle() in main.cpp.
// Logic, structure, comments, and all ProvenanceLedger::Record() calls are
// preserved exactly as they appeared in the original function.
// ---------------------------------------------------------------------------
void AutonomousEngine::Tick()
{
    auto& ctx = PManContext::Get();

    // [FIX] Stop decision loop if protection is paused
    if (ctx.isPaused.load()) return;

    // Graceful Degradation: If COM failed at startup, the engine must not
    // operate in a partially-initialized state. Demote all decisions to safe inaction.
    if (ctx.fault.comFailure.load()) {
        Log("[FAULT] COM not initialized. AutonomousEngine demoted to BrainAction::Maintain.");
        return;
    }

    // 0. Outcome-Based Early Termination (Reactive Rollback Guard)
    // "Stop immediately if this is going badly."
    // We check if the active lease (from previous tick) is causing actual harm.
    if (ctx.subs.sandbox && ctx.subs.guard) {
        if (ctx.subs.sandbox->IsLeaseActive()) {
            if (ctx.subs.guard->ShouldAbort(m_lastPredicted, m_lastObserved)) {
                // Reality diverged dangerously -> IMMEDIATE STOP
                ctx.subs.sandbox->Rollback(); // Triggers Cooldown
                Log("Abort: OutcomeMismatch (Observed worse than predicted)");
            }
        }
    }

    // 1. SystemTelemetry (Capture State)
    SystemSignalSnapshot telemetry = CaptureSnapshot();
    
    // [FIX] Traffic Enforcer: Check for Reflex Signal
    if (PManContext::Get().subs.perf && PManContext::Get().subs.perf->ConsumeEmergencySignal()) {
        telemetry.requiresPerformanceBoost = true;
    }

    // Safety: Ensure subsystems are initialized
    if (!ctx.subs.governor || !ctx.subs.evaluator || !ctx.subs.arbiter) return;

    // Pre-Fetch Confidence State (for Decision gating)
    ConfidenceMetrics currentConfidence = {0.0, 0.0, 0.0};
    if (ctx.subs.confidence) {
        currentConfidence = ctx.subs.confidence->GetMetrics();
    }

    // Pre-Fetch Allowed Actions from Policy Contract
    std::unordered_set<int> currentAllowed;
    if (ctx.subs.policy) {
        auto& limits = ctx.subs.policy->GetLimits();
        currentAllowed = limits.allowedActions;
        
        // [FIX] Sync dynamic confidence thresholds from Policy to Arbiter
        ctx.subs.arbiter->SetConfidenceThresholds(
            limits.minConfidence.cpuVariance,
            limits.minConfidence.thermalVariance,
            limits.minConfidence.latencyVariance
        );
    } else {
        currentAllowed.insert((int)BrainAction::Maintain); 
    }

    // 2. PerformanceGovernor (Evaluate Telemetry)
    GovernorDecision priorities = ctx.subs.governor->Decide(telemetry);

    // [FIX] Pre-filter Governor's generic allowed action class against strict Policy Contract
    // This prevents the Evaluator from wasting cycles predicting forbidden actions.
    if (priorities.allowedActions == AllowedActionClass::PerformanceBoost) {
        if (currentAllowed.find((int)BrainAction::Boost_Process) == currentAllowed.end()) {
            priorities.allowedActions = AllowedActionClass::None;
        }
    }

    // 3. ConsequenceEvaluator (Predict Consequences)
    ConsequenceResult consequences = ctx.subs.evaluator->Evaluate(
        priorities.mode, 
        priorities.dominant, 
        priorities.allowedActions
    );

    // 4. DecisionArbiter (Decide)

    ArbiterDecision decision = ctx.subs.arbiter->Decide(priorities, consequences, currentConfidence, currentAllowed);

    // [GATE] Policy Enforcement Layer
    if (ctx.subs.policy && decision.selectedAction != BrainAction::Maintain) {
        if (!ctx.subs.policy->Validate(decision.selectedAction, currentConfidence.cpuVariance, currentConfidence.latencyVariance)) {
            // Demote to Counterfactuals
            decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::PolicyViolation});
            
            auto it = std::remove_if(decision.rejectedAlternatives.begin(), decision.rejectedAlternatives.end(), 
                [](const CounterfactualRecord& r){ return r.action == BrainAction::Maintain; });
            decision.rejectedAlternatives.erase(it, decision.rejectedAlternatives.end());

            BrainAction rejectedAction = decision.selectedAction;
            decision.selectedAction = BrainAction::Maintain;
            decision.reason = DecisionReason::HardRuleViolation;
            decision.isReversible = false;
            Log("[POLICY_VIOLATION] Action rejected by contract. ActionID: " + std::to_string((int)rejectedAction));
        }
    }

    // [GATE] External Verdict Interface (Jurisdictional Boundary)
    // "The system is not sovereign. It is a licensed operator."
    VerdictResult verdictResult = { false, "NONE", 0, "" };
    if (ctx.subs.verdict) {
        verdictResult = ctx.subs.verdict->Check(decision.selectedAction);

        if (!verdictResult.allowed) {
             // Demote to Counterfactuals
             if (decision.selectedAction != BrainAction::Maintain) {
                 decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::ExternalDenial});
             }

             // Remove Maintain from rejected list
             auto it = std::remove_if(decision.rejectedAlternatives.begin(), decision.rejectedAlternatives.end(), 
                 [](const CounterfactualRecord& r){ return r.action == BrainAction::Maintain; });
             decision.rejectedAlternatives.erase(it, decision.rejectedAlternatives.end());

             // Force Maintain
             decision.selectedAction = BrainAction::Maintain;
             decision.reason = DecisionReason::HardRuleViolation;
             decision.isReversible = false;
             
             // Log only on state change or significant denial to avoid spam, or verbose
             // Prompt says "Missing / expired / malformed verdicts fail closed"
             static std::string lastVerdictReason = "";
             if (verdictResult.reason != lastVerdictReason) {
                Log("[EXTERNAL_VERDICT] Authority Revoked: " + verdictResult.reason);
                lastVerdictReason = verdictResult.reason;
             }
        }
    } else {
        // Missing Module -> Fail Closed
        decision.selectedAction = BrainAction::Maintain;
        decision.isReversible = false;
        verdictResult.stateStr = "MISSING_MODULE";
    }

    //  Intent Persistence (Consecutive-Approval Gate)
    bool intentStable = true;
    uint32_t intentCount = 0;
    bool intentReset = false;
    BrainAction rawIntent = decision.selectedAction;

    if (ctx.subs.intent) {
        ctx.subs.intent->Observe(rawIntent);
        intentStable = ctx.subs.intent->IsStable(3);
        intentCount = ctx.subs.intent->GetCount();
        intentReset = ctx.subs.intent->WasReset();

        if (!intentStable && decision.selectedAction != BrainAction::Maintain) {
            // Demote to Counterfactuals
            decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::UnstableIntent});
            
            // Remove Maintain from rejected list
            auto it = std::remove_if(decision.rejectedAlternatives.begin(), decision.rejectedAlternatives.end(), 
                [](const CounterfactualRecord& r){ return r.action == BrainAction::Maintain; });
            decision.rejectedAlternatives.erase(it, decision.rejectedAlternatives.end());

            // Veto
            decision.selectedAction = BrainAction::Maintain;
            decision.reason = DecisionReason::None; 
            decision.isReversible = false;
        }
    }

    // 5. ShadowExecutor (Simulate Only)
    PredictedStateDelta shadowDelta = {0, 0, 0};
    if (ctx.subs.shadow) {
        shadowDelta = ctx.subs.shadow->Simulate(decision, telemetry);
    }

    // Provenance Integrity Check (Hard Constraint)
    if (ctx.subs.provenance && !ctx.subs.provenance->IsProvenanceSecure()) {
        decision.selectedAction = BrainAction::Maintain;
        decision.reason = DecisionReason::HardRuleViolation; 
        decision.isReversible = false;
        Log("Abort: Provenance Ledger Unhealthy");
    }

    // Authority Budget & Pre-Execution Capture
    int actionCost = 0;
    int budgetBefore = 0;
    bool budgetExhausted = false;
    
	if (ctx.subs.budget) {
        budgetBefore = ctx.subs.budget->GetUsed();
        bool rejectBudget = false;
        
        // Budget Exhaustion Notification
        static bool s_exhaustionNotified = false;

        if (ctx.subs.budget->IsExhausted()) {
             if (!s_exhaustionNotified) {
                 TrayAnimator::Get().ShowNotification(
                     L"Authority Budget Exhausted", 
                     L"The AI has reached its intervention limit. Click here to reset or adjust Policy.", 
                     NIIF_WARNING
                 );
                 s_exhaustionNotified = true;
             }
             rejectBudget = true;
             budgetExhausted = true;
        } else {
             s_exhaustionNotified = false; // Reset state if budget is replenished
             
             actionCost = ctx.subs.budget->GetCost(decision.selectedAction);
             if (!ctx.subs.budget->CanSpend(actionCost)) {
                 rejectBudget = true;
             }
        }

        if (rejectBudget && decision.selectedAction != BrainAction::Maintain) {
             // Demote to Counterfactuals
             decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::BudgetInsufficient});
             
             // Remove Maintain from rejected list
             auto it = std::remove_if(decision.rejectedAlternatives.begin(), decision.rejectedAlternatives.end(), 
                 [](const CounterfactualRecord& r){ return r.action == BrainAction::Maintain; });
             decision.rejectedAlternatives.erase(it, decision.rejectedAlternatives.end());

             decision.selectedAction = BrainAction::Maintain;
             decision.reason = DecisionReason::GovernorRestricted;
             decision.isReversible = false;
             actionCost = 0; // [FIX] Prevent spending for rejected action
        }
    }

    // 6. Sandbox Executor (Time-Bound Authority Lease)
    // Physically execute (or maintain) the action on a safe target.
    // Checks lease expiry and enforces automatic reversion.
    SandboxResult sbResult = { false, false, false, "None" };
    if (ctx.subs.sandbox) {
        sbResult = ctx.subs.sandbox->TryExecute(decision);

        // Budget Spending
        // Only spend if the action was committed and wasn't forced to Maintain by budget check
        if (sbResult.committed && !budgetExhausted) {
             if (ctx.subs.budget) ctx.subs.budget->Spend(actionCost);
        }
    }

    // Decision Provenance Recording (The Receipt)
    bool faultActive = ctx.fault.ledgerWriteFail || ctx.fault.budgetCorruption || 
                       ctx.fault.sandboxError || ctx.fault.intentInvalid || 
                       ctx.fault.confidenceInvalid;

    if (ctx.subs.provenance) {
        // Also record when an API-level failure was pushed as a counterfactual,
        // so the Ledger captures "TargetAccessDenied" and "ApiFailure" events
        bool hasApiRejection = std::any_of(
            decision.rejectedAlternatives.begin(), decision.rejectedAlternatives.end(),
            [](const CounterfactualRecord& r) {
                return r.reason == RejectionReason::TargetAccessDenied ||
                       r.reason == RejectionReason::ApiFailure;
            });
        bool shouldRecord = (decision.selectedAction != BrainAction::Maintain && sbResult.executed) ||
                            hasApiRejection;
        
        // Force record if a fault is active (Audit Proof of Failure)
        if (faultActive) shouldRecord = true;

        if (shouldRecord) {
            DecisionJustification justification;
            justification.actionType = decision.selectedAction;
            justification.timestamp = GetTickCount64();
            
            // Confidence Snapshot
            justification.cpuVariance = currentConfidence.cpuVariance;
            justification.thermalVariance = currentConfidence.thermalVariance;
            justification.latencyVariance = currentConfidence.latencyVariance;
            
            // Context
            justification.intentStabilityCount = intentCount;
            justification.authorityBudgetBefore = budgetBefore;
            justification.authorityCost = actionCost;
            
            // Outcomes
            justification.sandboxResult = sbResult;
            justification.policyHash = ctx.subs.policy ? ctx.subs.policy->GetHash() : "NONE";
            justification.counterfactuals = decision.rejectedAlternatives;
            
            // External Verdict Capture
            justification.externalVerdict.state = verdictResult.stateStr;
            justification.externalVerdict.expiresAt = verdictResult.expiresAt;

            // [HARD SAFETY] Counterfactual Integrity Check
            if (justification.counterfactuals.empty() && justification.actionType == BrainAction::Maintain) {
                // If we are Maintaining, we MUST have reasons why we rejected others. 
                // Empty list implies we didn't check, which is an authority failure.
                // Exception: If universe size is 1 (impossible here).
                
                // Note: If we selected an action (not Maintain), list might be empty if universe is small, 
                // but with 6 actions, there should always be rejected ones.
                
                if (PManContext::Get().subs.provenance) {
                    // Force Fault
                    PManContext::Get().fault.ledgerWriteFail = true;
                    Log("[CRITICAL] Counterfactual Capture Failed. Authority Revoked.");
                }
            }
            
            // Mark Reason if fault active
            if (faultActive) {
                justification.sandboxResult.reason = "Fault:Active";
                justification.finalCommitted = false; // Faults force failure
                Log("[FAULT] Recording Fault Event in Provenance Ledger.");
            } else {
                justification.finalCommitted = sbResult.committed;
            }

            justification.rollbackGuardTriggered = false; // We reached execution, so guard was passive
            
            ctx.subs.provenance->Record(justification);
        }
    }

    // 7. Conditional Execution (The "1 Bit" of Authority)
    // If the action was not marked reversible (and committed) by Sandbox, force inaction.
    BrainAction executedAction = decision.selectedAction;
    if (!decision.isReversible) {
        decision.selectedAction = BrainAction::Maintain;
    }

    // 8. RealitySampler (Measure actual outcome)
    // Capture state AFTER the tick (and potential action, if it were enabled)
    SystemSignalSnapshot telemetry_after = CaptureSnapshot();
    
    ObservedStateDelta observed = {0, 0, 0};
    if (ctx.subs.reality) {
        observed = ctx.subs.reality->Measure(telemetry, telemetry_after);
    }

    // 8. PredictionLedger (Compute Error)
    PredictionError error = {0, 0, 0};
    if (ctx.subs.ledger) {
        error = ctx.subs.ledger->Compute(shadowDelta, observed);
    }

    // 9. ConfidenceTracker (Observe Error)
    ConfidenceMetrics confMetrics = {0.0, 0.0, 0.0};
    if (ctx.subs.confidence) {
        ctx.subs.confidence->Observe(error);
        confMetrics = ctx.subs.confidence->GetMetrics();
    }

    // [FIX] Feed reality back to the Predictive Model (The Brain) so it actually learns
    if (ctx.subs.model && executedAction != BrainAction::Maintain && sbResult.committed) {
        OptimizationFeedback fb = {};
        fb.mode = priorities.mode;
        fb.dominant = priorities.dominant;
        fb.action = executedAction;
        fb.cpuDelta = observed.cpuLoadDelta;
        fb.memDelta = 0.0;
        fb.diskDelta = observed.diskQueueDelta;
        fb.latencyDelta = observed.latencyDelta;
        fb.userInterrupted = false;
        
        ctx.subs.model->Feedback(priorities.mode, priorities.dominant, priorities.allowedActions, consequences.cost, fb);
    }

    // 10. Logger (Trace full decision chain + Reality + Error + Confidence + Sandbox + Budget)
    std::string budgetLog = "";
    if (ctx.subs.budget) {
        if (ctx.subs.budget->IsExhausted()) {
            budgetLog = " Budget:[Exhausted -> Authority Locked]";
        } else {
            budgetLog = " Budget:[" + std::to_string(ctx.subs.budget->GetUsed()) + 
                        "/" + std::to_string(ctx.subs.budget->GetMax()) + "]";
        }
    }

    // [FIX] Log Silencer: Only log if we actually DID something or failed to do something intended
    if (decision.selectedAction != BrainAction::Maintain || sbResult.executed) {
        // "Logs show Governor -> Evaluator -> Arbiter -> Shadow -> Sandbox -> Reality -> Error -> Confidence"
        std::string log = "[TICK] Gov:" + std::to_string((int)priorities.dominant) + 
                          " EvalCost:" + std::to_string(consequences.cost.cpuDelta) + 
                          budgetLog +
                          " ArbAct:" + std::to_string((int)decision.selectedAction) + 
                          " Shadow:[" + std::to_string(shadowDelta.cpuLoadDelta) + 
                          "," + std::to_string(shadowDelta.thermalDelta) + 
                          "," + std::to_string(shadowDelta.latencyDelta) + "]" +
                          " Sandbox:[" + (sbResult.committed ? "Committed" : "RolledBack/Rejected") +
                          "," + (sbResult.reversible ? "Rev" : "NonRev") +
                          "," + (sbResult.reason) + "]" +
                          (sbResult.cooldownRemaining > 0 ? " Cooldown:[Active (remaining=" + std::to_string(sbResult.cooldownRemaining) + "ms)]" : "") +
                          " Observed:[" + std::to_string(observed.cpuLoadDelta) + 
                          "," + std::to_string(observed.thermalDelta) + 
                          "," + std::to_string(observed.latencyDelta) + "]" +
                          " Error:[" + std::to_string(error.cpuError) + 
                          "," + std::to_string(error.thermalError) + 
                          "," + std::to_string(error.latencyError) + "]" +
                          " ConfidenceVar:[" + std::to_string(confMetrics.cpuVariance) +
                          "," + std::to_string(confMetrics.thermalVariance) +
                          "," + std::to_string(confMetrics.latencyVariance) + "]" +
                          " Intent:[" + (intentReset ? "Reset" : std::to_string((int)rawIntent)) + 
                          " (" + std::to_string(intentCount) + "/3)]" +
                          " Rsn:" + std::to_string((int)decision.reason);
        Log(log);
    }

    // Update persistent state for next tick's Outcome Guard
    m_lastPredicted = shadowDelta;
    m_lastObserved = observed;
}
