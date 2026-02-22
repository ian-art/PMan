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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "types.h"
#include "constants.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "config.h"
#include "sysinfo.h"
#include "policy.h"
#include "events.h"
#include "tweaks.h"
#include "services.h"
#include "services_watcher.h"
#include "restore.h"
#include "static_tweaks.h"
#include "memory_optimizer.h"
#include "network_monitor.h"
#include "input_guardian.h"
#include "gui_manager.h"
#include "dark_mode.h"
#include "log_viewer.h"
#include "sram_engine.h"
#include "lifecycle.h"
#include "executor.h" // [FIX] Required for Executor::Shutdown
#include "policy_optimizer.h" // [FIX] Defines PolicyOptimizer
#include "governor.h"
#include "consequence_evaluator.h"
#include "predictive_model.h" // Machine learning state prediction
#include "decision_arbiter.h"
#include "shadow_executor.h"
#include "reality_sampler.h"
#include "prediction_ledger.h"
#include "confidence_tracker.h"
#include "sandbox_executor.h"
#include "intent_tracker.h" // [FIX] Added missing include
#include "outcome_guard.h"
#include "authority_budget.h"
#include "provenance_ledger.h"
#include "policy_contract.h"
#include "external_verdict.h"
#include "context.h"
#include "tray_animator.h"
#include "ipc_server.h"
#include "responsiveness_manager.h"
#include "telemetry_agent.h" // Telemetry Agent
#include "heartbeat.h" // Watchdog Heartbeat
#include "crash_reporter.h" // Crash Reporting
#include <thread>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <objbase.h> // Fixed: Required for CoInitialize
#include <powrprof.h>
#include <pdh.h>
#include <shellapi.h> // Required for CommandLineToArgvW
#include <commctrl.h> // For Edit Control in Live Log
#include <deque>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <dwmapi.h>   // Required for DWM Dark Mode
#include <uxtheme.h>  // Required for Theme definitions
#include <array>

#pragma comment(lib, "PowrProf.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib") // For BITS monitoring
#pragma comment(lib, "Gdi32.lib") // Required for CreateFontW/DeleteObject
#pragma comment(lib, "Comctl32.lib") // Required for TaskDialog
#pragma comment(lib, "Dwmapi.lib") // DWM
#pragma comment(lib, "Uxtheme.lib") // UxTheme

// Force Linker to embed Manifest for Visual Styles (Required for TaskDialog)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Forward Declaration for Tab Redirect
namespace GuiManager { void OpenPolicyTab(); }

// GLOBAL VARIABLE
HINSTANCE g_hInst = nullptr;
static UINT g_wmTaskbarCreated = 0;

#define ID_TRAY_EXPORT_LOG 5001 // Unique ID for Audit Export

static std::atomic<bool> g_isCheckingUpdate{false};
// [FIX] RAII: Replaced raw GUID* with smart pointer to prevent leak/manual management
struct LocalFreeDeleter { void operator()(void* p) const { if (p) LocalFree(p); } };
static std::unique_ptr<GUID, LocalFreeDeleter> g_pSleepScheme;
static UniqueHandle g_hGuardProcess; // Handle to the watchdog process
static uint64_t g_resumeStabilizationTime = 0; // Replaces detached sleep thread;

// Removed LaunchProcessAsync (Dead Code / Unsafe Detach)
// All process launches now use synchronous CreateProcessW or the unified background worker.

// --- Authoritative Control Loop ---

static SystemSignalSnapshot CaptureSnapshot() {
    // [OPTIMIZED] Non-blocking read from background telemetry agent
    // Offloads PDH and GetSystemTimes to worker thread
    if (auto& agent = PManContext::Get().subs.telemetry) {
        return agent->GetLatestSnapshot();
    }
    return {}; // Safety fallback
}

// Persistent state for Outcome Guard (Previous Tick)
static PredictedStateDelta g_lastPredicted = {0,0,0};
static ObservedStateDelta g_lastObserved = {0,0,0};

static void RunAutonomousCycle() {
    auto& ctx = PManContext::Get();

    // [FIX] Stop decision loop if protection is paused
    if (ctx.isPaused.load()) return;

    // 0. Outcome-Based Early Termination (Reactive Rollback Guard)
    // "Stop immediately if this is going badly."
    // We check if the active lease (from previous tick) is causing actual harm.
    if (ctx.subs.sandbox && ctx.subs.guard) {
        if (ctx.subs.sandbox->IsLeaseActive()) {
            if (ctx.subs.guard->ShouldAbort(g_lastPredicted, g_lastObserved)) {
                // Reality diverged dangerously -> IMMEDIATE STOP
                ctx.subs.sandbox->Rollback(); // Triggers Cooldown
                Log("Abort: OutcomeMismatch (Observed worse than predicted)");
            }
        }
    }

    // 1. SystemTelemetry (Capture State)
    SystemSignalSnapshot telemetry = CaptureSnapshot();
    
    // [FIX] Traffic Enforcer: Check for Reflex Signal
    if (g_perfGuardian.ConsumeEmergencySignal()) {
        telemetry.requiresPerformanceBoost = true;
    }

    // Safety: Ensure subsystems are initialized
    if (!ctx.subs.governor || !ctx.subs.evaluator || !ctx.subs.arbiter) return;

    // Pre-Fetch Confidence State (for Decision gating)
    ConfidenceMetrics currentConfidence = {0.0, 0.0, 0.0};
    if (ctx.subs.confidence) {
        currentConfidence = ctx.subs.confidence->GetMetrics();
    }

    // 2. PerformanceGovernor (Evaluate Telemetry)
    GovernorDecision priorities = ctx.subs.governor->Decide(telemetry);

    // 3. ConsequenceEvaluator (Predict Consequences)
    ConsequenceResult consequences = ctx.subs.evaluator->Evaluate(
        priorities.mode, 
        priorities.dominant, 
        priorities.allowedActions
    );

    // 4. DecisionArbiter (Decide)
    // [FIX] Pass allowed actions to enable "Stability Disabled" logic
    std::unordered_set<int> currentAllowed;
    if (ctx.subs.policy) {
        auto& limits = ctx.subs.policy->GetLimits();
        currentAllowed = limits.allowedActions;
        
        // [FIX] Sync dynamic confidence thresholds from Policy to Arbiter
        // This ensures policy.json variance settings actually affect the Arbiter's logic.
        ctx.subs.arbiter->SetConfidenceThresholds(
            limits.minConfidence.cpuVariance,
            limits.minConfidence.thermalVariance,
            limits.minConfidence.latencyVariance
        );
    } else {
        // Fallback: If no policy, assume Maintain is allowed (Safety Default)
        currentAllowed.insert((int)BrainAction::Maintain); 
    }

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
        bool shouldRecord = (decision.selectedAction != BrainAction::Maintain && sbResult.executed);
        
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
    if (ctx.subs.model && decision.selectedAction != BrainAction::Maintain) {
        OptimizationFeedback fb = {};
        fb.mode = priorities.mode;
        fb.dominant = priorities.dominant;
        fb.action = decision.selectedAction;
        fb.cpuDelta = observed.cpuLoadDelta;
        fb.memDelta = 0.0;
        fb.diskDelta = 0.0;
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
    g_lastPredicted = shadowDelta;
    g_lastObserved = observed;
}

// [FIX] Secondary SEH barrier for the restore thread.
// Plain C-style function with no local C++ objects → __try/__except compiles without C2712.
// If WaitForEventLogRpc races and the exception still fires, this catches it at the thread
// boundary before it becomes unhandled and reaches the crash reporter's termination path.
static void RestorePointThreadSafe()
{
    __try {
        EnsureStartupRestorePoint();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Cannot call Log() here — no C++ objects in __try/__except scope.
        // Log absence of [BACKUP] success message will indicate the exception path was hit.
        OutputDebugStringA("[PMAN] Restore thread: SEH 0x6ba caught at thread boundary.\n");
    }
}

// --- Background Worker for Async Tasks ---
static std::thread g_backgroundWorker;
static std::mutex g_backgroundQueueMtx;
static std::deque<std::function<void()>> g_backgroundTasks;
static std::condition_variable g_backgroundCv;
static std::atomic<bool> g_backgroundRunning{ true };

static void BackgroundWorkerThread() {
    while (g_backgroundRunning.load()) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(g_backgroundQueueMtx);
            g_backgroundCv.wait(lock, [] {
                return !g_backgroundTasks.empty() || !g_backgroundRunning.load();
            });

            if (!g_backgroundRunning.load() && g_backgroundTasks.empty()) break;

            if (!g_backgroundTasks.empty()) {
                task = std::move(g_backgroundTasks.front());
                g_backgroundTasks.pop_front();
            }
        }
        if (task) task();
    }
}

// Instance provided by responsiveness_manager.h/cpp integration or declared here
static ResponsivenessManager g_responsivenessManager;

// LogViewer moved to log_viewer.cpp / log_viewer.h

// Helper for initial reg read
static DWORD ReadCurrentPrioritySeparation()
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                            0, KEY_QUERY_VALUE, &key);
    if (rc != ERROR_SUCCESS) return 0xFFFFFFFF;
    
    DWORD val = 0;
    DWORD size = sizeof(val);
    rc = RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);
    RegCloseKey(key);
    
    return (rc == ERROR_SUCCESS) ? val : 0xFFFFFFFF;
}

// [MOVED] Registry Guard implementation moved to restore.cpp

// Helper to update Tray Icon Tooltip with real-time status
static void UpdateTrayTooltip()
{
    std::wstring tip = L"Priority Manager";

    // 1. Protection Status
    if (g_userPaused.load()) {
        tip += L"\n\U0001F7E1 Status: PAUSED";
    } else {
        tip += L"\n\U0001F7E2 Status: Active";
    }

    // 2. Passive Mode (Idle Optimization Paused)
    if (g_pauseIdle.load()) {
        tip += L"\n\u2696 Passive: ON";
    }

    // 3. Awake Status
    if (g_keepAwake.load()) {
        tip += L"\n\u2600 Keep Awake: ON";
    }

    // 3. Current Mode
    if (g_sessionLocked.load()) {
         tip += L"\n\u1F3AE Mode: Gaming";
    }

    // SRAM Status
    LagState sramState = SramEngine::Get().GetStatus().state;
    if (sramState == LagState::SNAPPY) tip += L"\n\u26A1 System: Snappy";
    else if (sramState == LagState::SLIGHT_PRESSURE) tip += L"\n\u26A0 System: Pressure";
    else if (sramState == LagState::LAGGING) tip += L"\n\u26D4 System: Lagging";
    else if (sramState == LagState::CRITICAL_LAG) tip += L"\n\u2620 System: CRITICAL";

    // Delegate to module
    TrayAnimator::Get().UpdateTooltip(tip);
}

// Forward declaration for main program logic
int RunMainProgram(int argc, wchar_t** argv);

// Notification Helper
static void ShowSramNotification(LagState state) {
    if (state <= LagState::SLIGHT_PRESSURE) return; // Don't annoy user for minor things

    // Rate Limit: Max 1 notification every 30 seconds
    static uint64_t lastNotify = 0;
    uint64_t now = GetTickCount64();
    if (now - lastNotify < 30000) return;
    lastNotify = now;

    std::wstring title = L"System Responsiveness Alert";
    std::wstring msg = L"";

    DWORD flags = NIIF_NONE;
    if (state == LagState::LAGGING) {
        msg = L"System is experiencing lag. Optimization scans have been deferred to restore responsiveness.";
        flags = NIIF_WARNING;
    } else if (state == LagState::CRITICAL_LAG) {
        msg = L"CRITICAL LAG DETECTED. Entering 'Do No Harm' mode. All background operations stopped.";
        flags = NIIF_ERROR;
    }

    TrayAnimator::Get().ShowNotification(title, msg, flags);
}

// --- Custom Tray Animation Helpers ---
// Logic moved to tray_animator.cpp

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Re-add icon if Explorer restarts (TaskbarCreated message)
    if (g_wmTaskbarCreated && uMsg == g_wmTaskbarCreated)
    {
        TrayAnimator::Get().OnTaskbarRestart();
        return 0;
    }

    switch (uMsg)
    {
    case WM_CREATE:
        // Initialize Tray Animation Subsystem
        TrayAnimator::Get().Initialize(g_hInst, hwnd);
        
        // Restore saved state
        if (g_iconTheme != L"Default") {
            TrayAnimator::Get().SetTheme(g_iconTheme);
        }
        TrayAnimator::Get().SetPaused(g_userPaused.load());
        
        UpdateTrayTooltip(); // Set initial text

        // [DARK MODE] Apply Centralized Dark Mode
        DarkMode::ApplyToWindow(hwnd);
        // Keep heartbeat alive during modal loops (e.g., TrackPopupMenuEx, Apply Tweaks)
        SetTimer(hwnd, 9999, 1000, nullptr);
        return 0;

    // [DARK MODE] Refresh Menu Themes if system theme changes
    case WM_TIMER:
        if (wParam == 9999) {
            if (auto* hb = PManContext::Get().runtime.pHeartbeat) {
                hb->counter.fetch_add(1, std::memory_order_relaxed);
                hb->last_tick = GetTickCount64();
            }
            return 0;
        }
        TrayAnimator::Get().OnTimer(wParam);
        return 0;

    case WM_THEMECHANGED:
    case WM_SETTINGCHANGE:
        DarkMode::RefreshTheme();      // Flushes the Windows menu theme cache
        DarkMode::ApplyToWindow(hwnd);
        LogViewer::ApplyTheme();       // Update log window if open
        return 0;

    case WM_TRAYICON:
        // Handle Balloon Click (NIN_BALLOONUSERCLICK = 0x0405)
        if (lParam == 0x0405) {
            // If budget is exhausted, redirect user to Policy tab
            if (PManContext::Get().subs.budget && PManContext::Get().subs.budget->IsExhausted()) {
                 GuiManager::OpenPolicyTab();
            }
        }
        // Double Click -> Open Neural Center
        else if (lParam == WM_LBUTTONDBLCLK) {
            GuiManager::ShowConfigWindow();
            // Suppress the trailing WM_LBUTTONUP that follows this double-click
            // to prevent the menu from popping up over the window.
            static bool s_suppressMenu = true; 
            // Note: We use a static flag that persists to the next message
            SetPropW(hwnd, L"PMan_SuppressMenu", (HANDLE)1);
            return 0;
        }
        else if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            // Check suppression flag
            if (lParam == WM_LBUTTONUP) {
                if (GetPropW(hwnd, L"PMan_SuppressMenu")) {
                    RemovePropW(hwnd, L"PMan_SuppressMenu");
                    return 0;
                }
            }

            SetForegroundWindow(hwnd);
            
            // Ensure owner window state is current before menu creation
            DarkMode::ApplyToWindow(hwnd);
            
            HMENU hMenu = CreatePopupMenu();

            // Apply Dark Mode styles to the context menu
            DarkMode::ApplyToMenu(hMenu);

            // --- Icon Management ---
            std::vector<HBITMAP> menuBitmaps;
            bool isDark = DarkMode::IsEnabled();
            
            auto SetMenuIcon = [&](HMENU hM, UINT id, UINT iconLight, UINT iconDark, bool byPos = false) {
                UINT iconId = isDark ? iconDark : iconLight;
                HBITMAP hBmp = IconToBitmapPARGB32(g_hInst, iconId, 16, 16);
                if (hBmp) {
                    MENUITEMINFOW mii = { sizeof(mii) };
                    mii.fMask = MIIM_BITMAP;
                    mii.hbmpItem = hBmp;
                    SetMenuItemInfoW(hM, id, byPos, &mii);
                    menuBitmaps.push_back(hBmp);
                }
            };

            // 0. PMan Neural Center
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EDIT_CONFIG, L"PMan Neural Center");
            SetMenuIcon(hMenu, ID_TRAY_EDIT_CONFIG, IDI_TRAY_L_CP, IDI_TRAY_D_CP);
            
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

            bool paused = g_userPaused.load();

            // 1. Dashboards Submenu
            HMENU hDashMenu = CreatePopupMenu();
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_LIVE_LOG, L"Live Log Viewer");
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_OPEN_DIR, L"Open Log Folder");
            AppendMenuW(hDashMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hDashMenu, MF_STRING, ID_TRAY_EXPORT_LOG, L"Export Authority Log (JSON)");
            
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hDashMenu, L"Monitor & Logs");
            // Set icon for "Monitor & Logs" (Last item added)
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_LOG, IDI_TRAY_D_LOG, true);

            // --- Theme Selection Submenu ---
            HMENU hThemeMenu = CreatePopupMenu();
            AppendMenuW(hThemeMenu, MF_STRING | (g_iconTheme == L"Default" ? MF_CHECKED : 0), ID_TRAY_THEME_BASE, L"Default (Embedded)");
            
            std::vector<std::wstring> themes = TrayAnimator::Get().ScanThemes();
            int themeId = ID_TRAY_THEME_BASE + 1;
            for (const auto& theme : themes) {
                bool isSelected = (g_iconTheme == theme);
                AppendMenuW(hThemeMenu, MF_STRING | (isSelected ? MF_CHECKED : 0), themeId++, theme.c_str());
            }
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hThemeMenu, L"Icon Theme");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_THEME, IDI_TRAY_D_THEME, true);

            // 3. Controls Submenu
            HMENU hControlMenu = CreatePopupMenu();
            AppendMenuW(hControlMenu, MF_STRING | (paused ? MF_CHECKED : 0), ID_TRAY_PAUSE, paused ? L"Resume Activity" : L"Pause Activity");
            
            // Pause Idle Optimization (prevent CPU limiting during background tasks)
            bool idlePaused = g_pauseIdle.load();
            AppendMenuW(hControlMenu, MF_STRING | (idlePaused ? MF_CHECKED : 0), ID_TRAY_PAUSE_IDLE, L"Passive Mode");
			AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
			bool awake = g_keepAwake.load();
            AppendMenuW(hControlMenu, MF_STRING | (awake ? MF_CHECKED : 0), ID_TRAY_KEEP_AWAKE, L"Keep System Awake");
            AppendMenuW(hControlMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hControlMenu, MF_STRING, ID_TRAY_REFRESH_GPU, L"Refresh GPU");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hControlMenu, L"Controls");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_CONTROLS, IDI_TRAY_D_CONTROLS, true);

			AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

			// 4. Global Actions
            wchar_t self[MAX_PATH];
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();

            // Cache startup mode to avoid blocking UI with GetStartupMode()
            static int cachedMode = -1;
            static uint64_t lastCheck = 0;
            uint64_t now = GetTickCount64();

            if (cachedMode == -1 || (now - lastCheck > 5000)) {
                // Fast check (non-blocking if cached or assume previous)
                cachedMode = Lifecycle::GetStartupMode(taskName); 
                lastCheck = now;
            }
            int startupMode = cachedMode;

            HMENU hStartupMenu = CreatePopupMenu();
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 0 ? MF_CHECKED : 0), ID_TRAY_STARTUP_DISABLED, L"Disabled (Manual Start)");
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 1 ? MF_CHECKED : 0), ID_TRAY_STARTUP_ACTIVE,   L"Enabled (Active Optimization)");
            AppendMenuW(hStartupMenu, MF_STRING | (startupMode == 2 ? MF_CHECKED : 0), ID_TRAY_STARTUP_PASSIVE,  L"Enabled (Standby Mode)");
            
			AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hStartupMenu, L"Startup Behavior");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_STARTUP, IDI_TRAY_D_STARTUP, true);
            
            // 5. Help Submenu
            HMENU hHelpMenu = CreatePopupMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_HELP_USAGE, L"Help");
            AppendMenuW(hHelpMenu, MF_STRING | (g_isCheckingUpdate.load() ? MF_GRAYED : 0), ID_TRAY_UPDATE, L"Check for Updates");
            AppendMenuW(hHelpMenu, MF_STRING, ID_TRAY_ABOUT, L"About");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"Help");
            SetMenuIcon(hMenu, GetMenuItemCount(hMenu) - 1, IDI_TRAY_L_HELP, IDI_TRAY_D_HELP, true);
            
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SUPPORT, L"Support PMan \u2764\U0001F97A");
            SetMenuIcon(hMenu, ID_TRAY_SUPPORT, IDI_TRAY_L_SUPPORT, IDI_TRAY_D_SUPPORT);

            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
            SetMenuIcon(hMenu, ID_TRAY_EXIT, IDI_TRAY_L_EXIT, IDI_TRAY_D_EXIT);

            POINT pt; GetCursorPos(&pt);
            TrackPopupMenuEx(
				hMenu,
				TPM_BOTTOMALIGN | TPM_RIGHTALIGN | TPM_NOANIMATION,
				pt.x,
				pt.y,
				hwnd,
				nullptr
			);
            
            DestroyMenu(hControlMenu);
            // hConfigMenu removed
            DestroyMenu(hDashMenu);
            DestroyMenu(hThemeMenu);
            DestroyMenu(hHelpMenu);
            DestroyMenu(hMenu);
            
            // Cleanup bitmaps
            for (HBITMAP h : menuBitmaps) DeleteObject(h);
        }
        return 0;

    case WM_COMMAND:
    {
        DWORD wmId = LOWORD(wParam);
        
        // --- Theme Handler ---
        if (wmId >= ID_TRAY_THEME_BASE && wmId < ID_TRAY_THEME_BASE + 100) {
            std::wstring newTheme = L"Default";
            if (wmId != ID_TRAY_THEME_BASE) {
                std::vector<std::wstring> themes = TrayAnimator::Get().ScanThemes();
                int index = wmId - (ID_TRAY_THEME_BASE + 1);
                if (index >= 0 && index < themes.size()) {
                    newTheme = themes[index];
                }
            }
            TrayAnimator::Get().SetTheme(newTheme);
            SaveIconTheme(newTheme);
        }
        
        // --- New Handlers ---
        if (wmId == ID_TRAY_LIVE_LOG) {
            GuiManager::ShowLogWindow();
        }
        else if (wmId == ID_TRAY_OPEN_DIR) {
            ShellExecuteW(nullptr, L"open", GetLogPath().c_str(), nullptr, nullptr, SW_SHOW);
        }
        else if (wmId == ID_TRAY_EXPORT_LOG) {
            // Generate timestamped filename
            auto now = std::chrono::system_clock::now();
            auto t = std::chrono::system_clock::to_time_t(now);
            std::tm tm;
            localtime_s(&tm, &t);
            
            wchar_t filename[64];
            wcsftime(filename, 64, L"audit_dump_%Y%m%d_%H%M%S.json", &tm);
            
            std::filesystem::path path = GetLogPath() / filename;
            
            if (PManContext::Get().subs.provenance) {
                PManContext::Get().subs.provenance->ExportLog(path);
                
                // Optional: Show balloon tip to confirm
                TrayAnimator::Get().ShowNotification(L"Audit Export Complete", filename, NIIF_INFO);
            }
        }
		else if (wmId == ID_TRAY_EDIT_CONFIG) {
            GuiManager::ShowConfigWindow();
        }
		// --- End New Handlers ---

        else if (wmId == ID_TRAY_STARTUP_DISABLED) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            Lifecycle::UninstallTask(taskName);
        }
        else if (wmId == ID_TRAY_STARTUP_ACTIVE || wmId == ID_TRAY_STARTUP_PASSIVE) {
            wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring taskName = std::filesystem::path(self).stem().wstring();
            bool passive = (wmId == ID_TRAY_STARTUP_PASSIVE);
            Lifecycle::InstallTask(taskName, self, passive);
        }
        else if (wmId == ID_TRAY_EXIT) {
            DestroyWindow(hwnd);
        } 
        else if (wmId == ID_TRAY_ABOUT) {
            GuiManager::ShowAboutWindow();
        }
        else if (wmId == ID_TRAY_SUPPORT) {
            ShellExecuteW(nullptr, L"open", SUPPORT_URL, nullptr, nullptr, SW_SHOWNORMAL);
        }
        else if (wmId == ID_TRAY_HELP_USAGE) {
            GuiManager::ShowHelpWindow();
        }
        else if (wmId == ID_TRAY_UPDATE) {
            OpenUpdatePage();
        }
        else if (wmId == ID_TRAY_REFRESH_GPU) {
            // Simulate Win+Ctrl+Shift+B to reset graphics driver
            INPUT inputs[8] = {};

            // Press
            inputs[0].type = INPUT_KEYBOARD; inputs[0].ki.wVk = VK_LCONTROL;
            inputs[1].type = INPUT_KEYBOARD; inputs[1].ki.wVk = VK_LSHIFT;
            inputs[2].type = INPUT_KEYBOARD; inputs[2].ki.wVk = VK_LWIN;
            inputs[3].type = INPUT_KEYBOARD; inputs[3].ki.wVk = 0x42; // 'B' key

            // Release (Reverse order)
            inputs[4] = inputs[3]; inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[5] = inputs[2]; inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[6] = inputs[1]; inputs[6].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[7] = inputs[0]; inputs[7].ki.dwFlags = KEYEVENTF_KEYUP;

            if (SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT)) == ARRAYSIZE(inputs)) {
                Log("[USER] GPU Driver Refresh triggered manually.");
            } else {
                Log("[ERROR] Failed to send GPU refresh keystrokes: " + std::to_string(GetLastError()));
            }
        }
        else if (wmId == ID_TRAY_PAUSE) {
            bool p = !g_userPaused.load();
            g_userPaused.store(p);
            PManContext::Get().isPaused.store(p);

            // --- ANIMATION STATE SWITCH ---
            TrayAnimator::Get().SetPaused(p);
            // -----------------------------

            UpdateTrayTooltip(); 
            Log(p ? "[USER] Protection PAUSED." : "[USER] Protection RESUMED.");
            if (!p) g_reloadNow.store(true);
        }
        else if (wmId == ID_TRAY_PAUSE_IDLE) {
            bool p = !g_pauseIdle.load();
            g_pauseIdle.store(p);

            UpdateTrayTooltip(); // Refresh tooltip immediately

            Log(p ? "[USER] Idle Optimization PAUSED (CPU Limiting Disabled)." : "[USER] Idle Optimization RESUMED.");

            // Immediate effect: If we just paused, force the Idle Manager to think we are active
            // This restores all parked cores instantly.
            if (p) {
                g_idleAffinityMgr.OnIdleStateChanged(false); 
            }
        }
        else if (wmId == ID_TRAY_KEEP_AWAKE) {
            bool k = !g_keepAwake.load();
            g_keepAwake.store(k);

            if (k) {
                // Prevent Sleep (System) and Screen Off (Display)
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
                Log("[USER] Keep Awake ENABLED (System Sleep & Display Off blocked).");
            } else {
                // Clear flags, allow OS to sleep normally
                SetThreadExecutionState(ES_CONTINUOUS);
                Log("[USER] Keep Awake DISABLED (System power settings restored).");
            }
            UpdateTrayTooltip(); // Refresh Tooltip
        }
        return 0;
    } // End of WM_COMMAND Block

    case WM_DEVICECHANGE:
        // Invalidate cache on hardware/topology changes
        if (wParam == 0x0018 /* DBT_CONFIGCHANGED */) {
            Log("[HARDWARE] System configuration changed. Scheduling cache invalidation.");
            g_reloadNow.store(true);
        }
        return TRUE;

    case WM_QUERYENDSESSION:
        // OS is asking if it can shut down. Tell it yes.
        return TRUE;

    case WM_ENDSESSION:
        // Windows is shutting down or restarting right now. 
        // We have very limited time before the OS forcefully terminates the process.
        if (wParam == TRUE) {
            Log("[LIFECYCLE] Windows restart/shutdown detected. Emergency brain flush.");
            if (PManContext::Get().subs.model) {
                PManContext::Get().subs.model->Shutdown();
            }
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 9999);
        TrayAnimator::Get().Shutdown();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

// Separation of Core Logic for SEH Compatibility
// We rename the original logic to RunPMan so we can wrap it.
static int RunPMan(int argc, wchar_t* argv[])
{
	try {
	
    // [DARK MODE] Initialize Centralized Dark Mode Manager
	DarkMode::Initialize();

    // Initialize Crash Reporter (Black Box & Flight Recorder)
    // Must be initialized before Logger to capture startup failures
    CrashReporter::Initialize();
    
    // Initialize Telemetry-Safe Logger
    InitLogger();

    // Initialize Watchdog Heartbeat (Dedicated Thread)
    PManContext::Get().subs.heartbeat = std::make_unique<HeartbeatSystem>();
    PManContext::Get().subs.heartbeat->Initialize();

    // Lifecycle Management
    std::vector<std::thread> lifecycleThreads;

	// 1. Initialize Global Instance Handle (Required for Tray Icon)
    g_hInst = GetModuleHandle(nullptr);

    // Register system-wide message for Taskbar recreation detection
    g_wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    // 2. Hide Console Window immediately (Restored logic for Console Subsystem)
    // This is required because /SUBSYSTEM:CONSOLE always spawns a window initially.
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != nullptr)
    {
        ShowWindow(consoleWindow, SW_HIDE);
    }

    // 3. argc/argv are provided directly by wmain, no conversion needed.

    // Check for Update Mode (Self-Update)
    if (argc >= 4 && std::wstring(argv[1]) == L"--update") {
        return 0;
    }

    // Check for Guard Mode (Must be before Mutex check)
    if (argc >= 5 && (std::wstring(argv[1]) == L"--guard"))
    {
        DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        // Fixed: Removed redundant low/high split. Expecting direct value.
        DWORD val = std::wcstoul(argv[3], nullptr, 10); 
        std::wstring powerScheme = argv[4];
        
        RunRegistryGuard(pid, val, powerScheme);
        return 0;
    }

    // Fix Silent Install/Uninstall Support
    bool uninstall = false;
    bool silent = false;

	for (int i = 1; i < argc; i++)
    {
        std::wstring arg = argv[i];
		if (arg == L"--help" || arg == L"-h" || arg == L"/?")
        {
            std::wstring version = GetCurrentExeVersion();
            std::wstring msg;
            msg.reserve(512); // Pre-allocate to prevent reallocation fragmentation
            msg += L"Priority Manager (pman) v" + version + L"\n";
            msg += L"by Ian Anthony R. Tancinco\n\n";
            msg += L"Usage: pman.exe [OPTIONS]\n\n";
            msg += L"Options:\n";
            msg += L"  --help, -h, /?      Show this help message\n";
            msg += L"  --uninstall         Stop instances and remove startup task\n";
            msg += L"  --silent, /S         Run operations without message boxes\n";
            msg += L"  --paused             Start in paused mode (Protection Disabled)\n";
            msg += L"  --guard             (Internal) Registry safety guard\n\n";
            msg += L"Automated Windows Priority & Affinity Manager";

            MessageBoxW(nullptr, msg.c_str(), L"Priority Manager - Help", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
		else if (arg == L"--uninstall" || arg == L"/uninstall") uninstall = true;
        else if (arg == L"/S" || arg == L"/s" || arg == L"/silent" || arg == L"-silent" || arg == L"/quiet") silent = true;
        else if (arg == L"--paused") {
            g_userPaused.store(true);
            PManContext::Get().isPaused.store(true);
        }
    }

    if (!uninstall)
    {
        g_hMutex.reset(CreateMutexW(nullptr, TRUE, MUTEX_NAME));
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is already running.", 
                    L"Priority Manager", MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        }
    }
    else
    {
        g_hMutex = nullptr;
    }

    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);

std::wstring taskName = std::filesystem::path(self).stem().wstring();

    if (uninstall)
    {
        Lifecycle::TerminateExistingInstances();

		if (!Lifecycle::IsTaskInstalled(taskName))
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is not currently installed.\nAny running instances have been stopped.", 
                    L"Priority Manager", MB_OK | MB_ICONWARNING);
            }
            g_hMutex.reset();
            return 0;
        }

        Lifecycle::UninstallTask(taskName);

        if (!silent)
        {
            MessageBoxW(nullptr, 
                L"Priority Manager has been successfully uninstalled.\nAny running instance has been stopped and the startup task removed.", 
                L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }

        g_hMutex.reset();
        return 0;
    }

	bool taskExists = Lifecycle::IsTaskInstalled(taskName);

    if (!taskExists)
    {
        // Install in Active mode (false for passive), with /S implied by Lifecycle::InstallTask default logic
        if (Lifecycle::InstallTask(taskName, self, false)) 
        {
             // Wait briefly to ensure task registration propagates
             Sleep(500);
             if (!silent)
                MessageBoxW(nullptr, L"Priority Manager installed successfully!\nIt will now run automatically at logon and is currently active.", L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
             if (!silent)
                MessageBoxW(nullptr, L"Failed to create startup task. Please run as Administrator.", L"Priority Manager - Error", MB_OK | MB_ICONWARNING);
             return 1;
        }
    }

    // Console was hidden at startup.
	
	Log("*********************************");
    Log("=== Priority Manager Starting ===");
    Log("All Levels Implemented: Session-Scoped | Cooldown | Registry Guard | Graceful Shutdown | OS Detection | Anti-Interference");
    
	// Initialize Performance Guardian
    g_perfGuardian.Initialize();

    // Initialize Smart Shell Booster
    g_explorerBooster.Initialize();

    // Initialize Input Responsiveness Guard
    g_inputGuardian.Initialize();

    // Initialize Secure IPC Core
    if (PManContext::Get().subs.ipc) {
        PManContext::Get().subs.ipc->Initialize();
    }

    // Initialize Telemetry Agent (Unblocks Main Loop)
    PManContext::Get().subs.telemetry = std::make_unique<TelemetryAgent>();
    PManContext::Get().subs.telemetry->Initialize();

    // Initialize Policy Optimizer
    PManContext::Get().subs.optimizer = std::make_unique<PolicyOptimizer>();
    PManContext::Get().subs.optimizer->Initialize();

    // Initialize Policy Contract (Boundary Formalization)
    PManContext::Get().subs.policy = std::make_unique<PolicyGuard>();
    // Note: If policy.json is missing, it fails open (safe defaults) or logs warning. 
    // It is read-only and will never be created by the system.
    if (PManContext::Get().subs.policy->Load(GetLogPath() / L"policy.json")) {
        Log("[INIT] Policy Contract loaded. Hash: " + PManContext::Get().subs.policy->GetHash());
        // [FIX] Apply Budget Limit from Policy
        if (PManContext::Get().subs.budget) {
            PManContext::Get().subs.budget->SetMax(PManContext::Get().subs.policy->GetLimits().maxAuthorityBudget);
        }
    } else {
        Log("[INIT] WARNING: policy.json missing or invalid. Using hardcoded safe defaults.");
        Log("[INIT] No policy.json found. Authority is DISABLED. To enable autonomy, provide a valid policy.json.");
    }

	// Initialize Smart Memory Optimizer
    g_memoryOptimizer.Initialize();

	// Initialize Service Watcher
    ServiceWatcher::Initialize();

    // Initialize SRAM (System Responsiveness Awareness Module)
    // Must be initialized before subsystems that depend on LagState
    SramEngine::Get().Initialize();

    DetectOSCapabilities();
    // [FIX] Use RestorePointThreadSafe: plain C function with __try/__except at thread entry.
    // No C++ objects in its scope, so MSVC C2712 does not apply.
    std::thread restoreThread(RestorePointThreadSafe);
    lifecycleThreads.push_back(std::move(restoreThread));
    
    DetectHybridCoreSupport();

    // Safety check: Restore services if they were left suspended from a crash
    if (g_caps.hasAdminRights && g_serviceManager.Initialize())
    {
		/*
        g_serviceManager.AddService(L"wuauserv", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
        g_serviceManager.AddService(L"BITS", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_START);
        */

        // Check if services are suspended (shouldn't be at startup)
        ScHandle scManager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (scManager)
        {
            auto CheckAndRecover = [&](const wchar_t* name) {
                ScHandle hSvc(OpenServiceW(scManager.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START));
                if (hSvc)
                {
                    // 1. Check if DISABLED first
            DWORD bytesNeeded = 0;
            // Fix C6031: Check return value (expect failure with buffer size)
            if (!QueryServiceConfigW(hSvc.get(), nullptr, 0, &bytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(bytesNeeded);
                        LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
                        if (QueryServiceConfigW(hSvc.get(), config, bytesNeeded, &bytesNeeded)) {
                            if (config->dwStartType == SERVICE_DISABLED) {
                                return; // Ignore disabled services
                            }
                        }
                    }

                    // 2. Check Status and Recover
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hSvc.get(), &status))
                    {
                        if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
                        {
                            Log(std::string("[STARTUP] WARNING: ") + WideToUtf8(name) + " was stopped/paused - attempting recovery");
                            StartServiceW(hSvc.get(), 0, nullptr);
                        }
                    }
                }
            };

            CheckAndRecover(L"wuauserv");
            CheckAndRecover(L"BITS");
        }
    }

    LoadConfig();
    
    g_hIocp.reset(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!g_hIocp)
    {
        Log("Failed to create IOCP: " + std::to_string(GetLastError()));
        return 1;
    }

    g_hShutdownEvent.reset(CreateEventW(nullptr, TRUE, FALSE, SHUTDOWN_EVENT_NAME));
    if (!g_hShutdownEvent)
    {
        Log("Failed to create shutdown event: " + std::to_string(GetLastError()));
    }
    
    // Helper to pin thread to Efficiency cores (ARM64/Hybrid safe)
    auto PinBackgroundThread = [](std::thread& t) {
        if (!g_eCoreSets.empty()) {
            // Pin to first two Efficiency cores
            DWORD_PTR mask = 0;
            if (g_eCoreSets.size() >= 1) mask |= (1ULL << g_eCoreSets[0]);
            if (g_eCoreSets.size() >= 2) mask |= (1ULL << g_eCoreSets[1]);
            SetThreadAffinityMask(t.native_handle(), mask);
        }
        else if (g_physicalCoreCount >= 4) {
            // Legacy Fallback: Use last 2 physical cores
            DWORD_PTR affinityMask = (1ULL << (g_physicalCoreCount - 1)) | (1ULL << (g_physicalCoreCount - 2));
            SetThreadAffinityMask(t.native_handle(), affinityMask);
        }
        // Always lower priority to prevent interference
        SetThreadPriority(t.native_handle(), THREAD_PRIORITY_LOWEST);
    };
    
    std::thread configThread(IocpConfigWatcher);
    PinBackgroundThread(configThread);

    // Initialize unified background worker
    g_backgroundWorker = std::thread(BackgroundWorkerThread);
    PinBackgroundThread(g_backgroundWorker);
    Sleep(100); // [POLISH] Stagger start
    
    std::thread etwThread;
    if (g_caps.canUseEtw)
    {
        etwThread = std::thread(EtwThread);
        PinBackgroundThread(etwThread);
        Sleep(100); // [POLISH] Stagger start
    }
    
    std::thread watchdogThread(AntiInterferenceWatchdog);
    PinBackgroundThread(watchdogThread);
    Sleep(100); // [POLISH] Stagger start
    
    // Start Memory Optimizer in background thread
    std::thread memOptThread([]() {
        g_memoryOptimizer.RunThread();
    });
    PinBackgroundThread(memOptThread);
    // Store for clean shutdown
    lifecycleThreads.push_back(std::move(memOptThread));
	
    // FIX: Check return value (C6031)
    HRESULT hrInit = CoInitialize(nullptr);
    if (FAILED(hrInit)) {
        Log("[INIT] CoInitialize failed: " + std::to_string(hrInit));
    }

    // Network Intelligence
    g_networkMonitor.Initialize();
    
    HWINEVENTHOOK hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
                                         nullptr, WinEventProc, 0, 0,
                                         WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hook) 
    { 
        Log("SetWinEventHook failed: " + std::to_string(GetLastError()));
    }
    
	WNDCLASSW wc{}; 
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = L"PMHidden";
    wc.hInstance = g_hInst; // FIX: Use global instance handle
    RegisterClassW(&wc);
    
	// Parent must be nullptr (Top-level) for Tray Icon to receive events reliably
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"PriorityManagerTray", 0, 0, 0, 0, 0, 
                              nullptr, nullptr, g_hInst, nullptr); // FIX: Use global instance handle
    RegisterPowerNotifications(hwnd);
    
    // Register for Raw Input to track user activity (Keyboard & Mouse) for Explorer Booster
    RAWINPUTDEVICE Rid[2];
    // Keyboard
    Rid[0].usUsagePage = 0x01; 
    Rid[0].usUsage = 0x06; 
    Rid[0].dwFlags = RIDEV_INPUTSINK;   
    Rid[0].hwndTarget = hwnd;
    // Mouse
    Rid[1].usUsagePage = 0x01; 
    Rid[1].usUsage = 0x02; 
    Rid[1].dwFlags = RIDEV_INPUTSINK; 
    Rid[1].hwndTarget = hwnd;

    if (!RegisterRawInputDevices(Rid, 2, sizeof(Rid[0]))) {
        Log("[INIT] Raw Input registration failed: " + std::to_string(GetLastError()));
    } else {
        Log("[INIT] Raw Input registered for idle detection");
    }

    Log("Background mode ready - monitoring foreground applications");
    
    DWORD currentSetting = ReadCurrentPrioritySeparation();
    if (currentSetting != 0xFFFFFFFF)
    {
        Log("Current system setting: " + GetModeDescription(currentSetting));
        g_originalRegistryValue = currentSetting;
        g_cachedRegistryValue.store(currentSetting);
        
        // Launch Crash-Proof Guard
        if (g_restoreOnExit.load())
        {
            // Capture handle for lifecycle management
            HANDLE hGuard = LaunchRegistryGuard(currentSetting);
            g_hGuardProcess.reset(hGuard);
            
            if (!g_hGuardProcess || g_hGuardProcess.get() == INVALID_HANDLE_VALUE) {
                Log("[CRITICAL] Failed to launch Registry Guard. Crash protection disabled.");
                g_hGuardProcess.reset();
            }
        }
    }
    else
    {
        Log("WARNING: Unable to read current registry setting");
	}
    
	MSG msg;
    // FIX: Use 64-bit time tracking to prevent overflow issues (C28159)
    static uint64_t g_lastExplorerPollMs = 0;

    while (g_running)
    {
        if (CheckForShutdownSignal())
        {
            PerformGracefulShutdown();
            break;
        }
        
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                g_running = false;
                break;
            }
            
            if (msg.message == WM_INPUT) 
            {
                // Signal user activity to Smart Shell Booster
                g_explorerBooster.OnUserActivity();
                
                // Input Responsiveness Guard
                // Monitor latency and boost foreground threads
                g_inputGuardian.OnInput(msg.time);
                
                DefWindowProc(msg.hwnd, msg.message, msg.wParam, msg.lParam);
            }
            			else if (msg.message == WM_POWERBROADCAST)
			{
				if (msg.wParam == PBT_APMQUERYSUSPEND || msg.wParam == PBT_APMSUSPEND)
				{
					Log("System suspending - pausing operations to prevent memory corruption");
					g_isSuspended.store(true);
				}
				else if (msg.wParam == PBT_APMRESUMEAUTOMATIC || msg.wParam == PBT_APMRESUMESUSPEND)
				{
					Log("System resumed - waiting 5s for kernel stability");

					// State-based delay instead of detached thread
					g_resumeStabilizationTime = GetTickCount64() + 5000;
					g_isSuspended.store(true); // Keep suspended until stabilization
				}
				else if (msg.wParam == PBT_POWERSETTINGCHANGE)
				{
					g_reloadNow = true;
				}
			}
            
            TranslateMessage(&msg); // [FIX] Convert keystrokes to characters for GUI input
            DispatchMessage(&msg);
        }
        
		if (g_reloadNow.exchange(false))
        {
            // [PERF FIX] Offload to persistent worker thread
            {
                std::lock_guard<std::mutex> lock(g_backgroundQueueMtx);
                g_backgroundTasks.push_back([]() {
                    Sleep(250);
                    // [CACHE] Atomic destruction on Config Reload
                    g_sessionCache.store(nullptr, std::memory_order_release);
                    Sleep(250);
                    LoadConfig();

                    // [FIX] Reload Policy and Sync Budget
                    if (PManContext::Get().subs.policy) {
                        PManContext::Get().subs.policy->Load(GetLogPath() / L"policy.json");
                        
                        // [SYNC] Push new thresholds to Arbiter immediately
                        if (PManContext::Get().subs.arbiter) {
                             auto& limits = PManContext::Get().subs.policy->GetLimits();
                             PManContext::Get().subs.arbiter->SetConfidenceThresholds(
                                limits.minConfidence.cpuVariance,
                                limits.minConfidence.thermalVariance,
                                limits.minConfidence.latencyVariance
                             );
                        }
                    }
                    
                    // [RECOVERY] Sync Budget Cap (But do NOT reset usage)
                    // Changing config.ini (games/apps) should not grant budget amnesty.
                    // Only a Policy change (maxAuthorityBudget) should affect the ceiling.
                    if (PManContext::Get().subs.budget) {
                        if (PManContext::Get().subs.policy) {
                            PManContext::Get().subs.budget->SetMax(PManContext::Get().subs.policy->GetLimits().maxAuthorityBudget);
                        }
                        // REMOVED: PManContext::Get().subs.budget->ResetByExternalSignal();
                    }
                });
            }
            g_backgroundCv.notify_one();
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        // Handle Resume Stabilization (Non-blocking)
        if (g_resumeStabilizationTime > 0) {
             if (GetTickCount64() >= g_resumeStabilizationTime) {
                 g_isSuspended.store(false);
                 g_resumeStabilizationTime = 0;
                 Log("System stabilized - resuming operations");
             }
        }

        // GUI Rendering Integration
        // [FIX] Protection: Stop rendering if system is suspended/stabilizing to prevent D3D crash
        if (GuiManager::IsWindowOpen() && !g_isSuspended.load()) {
            GuiManager::RenderFrame();
        }

        // Wait for messages with timeout - efficient polling that doesn't spin CPU
        // Use MsgWaitForMultipleObjects to stay responsive to inputs/shutdown while waiting
        // Reduced timeout to 16ms (~60 FPS) only when GUI is open to ensure smooth rendering
        DWORD waitTimeout = GuiManager::IsWindowOpen() ? 16 : 100;
        
        // Fix: Use local handle for array pointer requirement
        HANDLE hShutdown = g_hShutdownEvent.get();
        DWORD waitResult = MsgWaitForMultipleObjects(1, &hShutdown, FALSE, waitTimeout, QS_ALLINPUT);

        // [SAFETY] Fix C4189 & Prevent CPU spin if API fails
        if (waitResult == WAIT_FAILED) {
            Sleep(100); 
            continue;
        }

        // [OPTIMIZATION] If shutdown event signaled, skip tick logic to exit faster
        if (waitResult == WAIT_OBJECT_0) {
            continue;
        }
        
        // [FIX] MOVED OUTSIDE: Check tick timers regardless of input state
        // This ensures scanning happens even if the user is moving the mouse
        {
            // Calculate adaptive polling interval based on idle state
            // FIX: Use GetTickCount64 (C28159)
            uint64_t now = GetTickCount64();
            uint64_t idleDurationMs = now - g_explorerBooster.GetLastUserActivity();
            uint32_t thresholdMs = g_explorerBooster.GetIdleThreshold();
            
            // Adaptive poll rate: poll faster when approaching idle threshold (within 5s)
            bool approachingIdle = (idleDurationMs > 0 && idleDurationMs < thresholdMs && 
                                   idleDurationMs > (thresholdMs - 5000));
            uint32_t pollIntervalMs = approachingIdle ? 250 : 2000;

            // Rate limit the tick calls to prevent CPU spinning
            if ((now - g_lastExplorerPollMs) >= pollIntervalMs) {
                
                // FIX: Offload to persistent worker thread to protect Keyboard Hook
                {
                    std::lock_guard<std::mutex> lock(g_backgroundQueueMtx);
                    g_backgroundTasks.push_back([]{
						// Moved ExplorerBooster to background thread to prevent blocking the Keyboard Hook
						g_explorerBooster.OnTick();

					// Authoritative Control Loop
                    RunAutonomousCycle();

                    // Periodic Policy Optimization (Slow Loop)
                    static uint64_t lastOpt = 0;
                    if (GetTickCount64() - lastOpt > 60000) { // Every 1 minute
                        if (auto& opt = PManContext::Get().subs.optimizer) {
                            PolicyParameters newParams = opt->Optimize();
                            if (auto& gov = PManContext::Get().subs.governor) {
                                gov->UpdatePolicy(newParams);
                            }
                        }
                        lastOpt = GetTickCount64();
                    }

                    // [FIX] Periodic Brain Save (Every 15 minutes)
                    static uint64_t lastBrainSave = GetTickCount64();
                    if (GetTickCount64() - lastBrainSave > 900000) {
                        if (auto& model = PManContext::Get().subs.model) {
                            model->Shutdown(); // Writes m_stats to brain.bin
                        }
                        lastBrainSave = GetTickCount64();
                    }

						// Legacy/Advisory Updates (Data Collection Only)
						g_perfGuardian.OnPerformanceTick();
                        
                        // [FIX] Move heavy window checks to background to prevent main thread stutter
                        g_responsivenessManager.Update();
                    });
                }
                g_backgroundCv.notify_one();
                
                // Run Service Watcher
                ServiceWatcher::OnTick();

                // SRAM UI Updates
                static LagState lastKnownState = LagState::SNAPPY;
                LagState currentState = SramEngine::Get().GetStatus().state;
                
                if (currentState != lastKnownState) {
                    UpdateTrayTooltip(); // Refresh tooltip text
                    ShowSramNotification(currentState); // Show balloon if critical
                    lastKnownState = currentState;
                }
                
                g_lastExplorerPollMs = now;
            }
        }
    }
    
	if (hook) UnhookWinEvent(hook);
    
    // FIX: Explicitly unregister raw input devices (Renamed to RidCleanup to avoid redefinition error)
    RAWINPUTDEVICE RidCleanup[2] = {};
    RidCleanup[0].usUsagePage = 0x01; RidCleanup[0].usUsage = 0x06; RidCleanup[0].dwFlags = RIDEV_REMOVE; RidCleanup[0].hwndTarget = nullptr;
    RidCleanup[1].usUsagePage = 0x01; RidCleanup[1].usUsage = 0x02; RidCleanup[1].dwFlags = RIDEV_REMOVE; RidCleanup[1].hwndTarget = nullptr;
    RegisterRawInputDevices(RidCleanup, 2, sizeof(RAWINPUTDEVICE));

    // [FIX] Stop background worker BEFORE destroying UI/Subsystems to prevent deadlocks/use-after-free
    g_backgroundRunning = false;
    g_backgroundCv.notify_all();
    if (g_backgroundWorker.joinable()) g_backgroundWorker.join();

    GuiManager::Shutdown(); // Cleanup DX11/ImGui resources

	UnregisterPowerNotifications();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, g_hInst); // FIX: Use global instance handle
    
    CoUninitialize();
    
	g_running = false;
    g_networkMonitor.Stop(); // Stop Monitor
    if (PManContext::Get().subs.telemetry) PManContext::Get().subs.telemetry->Shutdown();
    if (PManContext::Get().subs.heartbeat) PManContext::Get().subs.heartbeat->Shutdown();
    g_explorerBooster.Shutdown();
    g_inputGuardian.Shutdown();
    g_memoryOptimizer.Shutdown();
    SramEngine::Get().Shutdown();

    // [FIX] Save Brain and Stop Executor
    // This ensures brain.bin is written to disk
    if (PManContext::Get().subs.executor) {
        PManContext::Get().subs.executor->Shutdown();
    }
    if (PManContext::Get().subs.optimizer) {
        PManContext::Get().subs.optimizer->Shutdown();
    }
    // [FIX] Save the Brain before exiting
    if (PManContext::Get().subs.model) {
        PManContext::Get().subs.model->Shutdown();
    }
	
    // Signal threads to wake up/stop
    if (g_hShutdownEvent) SetEvent(g_hShutdownEvent.get()); // Wakes Watchdog immediately
    StopEtwSession(); // Unblocks EtwThread (ProcessTrace returns)
    PostShutdown(); // Wakes IocpConfigWatcher
    
    // Background worker stopped earlier to ensure thread safety

    if (configThread.joinable()) configThread.join();
    if (etwThread.joinable()) etwThread.join();
    if (watchdogThread.joinable()) watchdogThread.join();
    
    // Join managed lifecycle threads
    for (auto& t : lifecycleThreads) {
        if (t.joinable()) t.join();
    }
    
    // RAII Cleanup handled by PManContext destructor
    // Explicitly release mutex ownership before closing handle
    if (g_hMutex) {
        ReleaseMutex(g_hMutex.get());
        g_hMutex.reset();
    }
    
    g_hIocp.reset();
    g_hShutdownEvent.reset();
    
    // Safety cleanup for Power Scheme
    if (g_pSleepScheme) {
        PowerSetActiveScheme(NULL, g_pSleepScheme.get());
        g_pSleepScheme.reset(); // Auto-calls LocalFree via Deleter
    }

    // Terminate Guard Process on graceful shutdown to prevent false positives
    if (g_hGuardProcess) {
        TerminateProcess(g_hGuardProcess.get(), 0);
        g_hGuardProcess.reset();
        Log("[GUARD] Watchdog process terminated gracefully.");
    }

    // [FIX] Manual Restoration on Graceful Exit
    if (g_restoreOnExit.load() && g_originalRegistryValue != 0xFFFFFFFF) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl", 
                         0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"Win32PrioritySeparation", 0, REG_DWORD, 
                          reinterpret_cast<const BYTE*>(&g_originalRegistryValue), sizeof(DWORD));
            RegCloseKey(hKey);
            Log("[SHUTDOWN] Restored original Priority Separation: " + std::to_string(g_originalRegistryValue));
        }
    }

    Log("=== Priority Manager Stopped ===");
    
    // Flush logs to disk before exit
    ShutdownLogger();

    return 0;

    } catch (const std::exception& e) {
        // Top-level crash boundary
        std::string msg = "[CRITICAL] Unhandled exception in main: ";
        msg += e.what();
        
        // Try logging to disk
        try {
            Log(msg);
            ShutdownLogger(); // Force flush
        } catch (...) {
            // Ignore secondary failures during crash handling
        }

        // Deterministic failure - visible to OS/User
        MessageBoxA(nullptr, msg.c_str(), "Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;

    } catch (...) {
        // Catch non-standard exceptions
        try {
            Log("[CRITICAL] Unknown non-standard exception caught in main.");
            ShutdownLogger();
        } catch (...) {
            // Ignore secondary failures
        }

        MessageBoxW(nullptr, L"Unknown fatal error occurred.", L"Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;
    }
}

// SEH Entry Point
// This wrapper catches hardware faults (Stack Overflow, Access Violation)
// that standard C++ try/catch blocks cannot handle.
int wmain(int argc, wchar_t* argv[])
{
    // Initialize Crash Reporter immediately
    CrashReporter::Initialize();

    __try {
        // [FIX] RunPMan is a static function in this file, not a member of GuiManager
        return RunPMan(argc, argv);
    }
    __except (CrashReporter::SehFilter(GetExceptionInformation())) {
        // The filter writes the dump and terminates the process.
        // We return -1 just to satisfy the signature if termination is delayed.
        return -1;
    }
}
