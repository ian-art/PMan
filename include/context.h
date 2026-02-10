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

#ifndef PMAN_CONTEXT_H
#define PMAN_CONTEXT_H

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <memory> 
#include <vector>
#include "types.h"

// Network Intelligence
enum class NetworkState {
    Offline = 0,    // No internet access
    Unstable = 1,   // High latency (>150ms) or packet loss
    Stable = 2      // Low latency, reliable connection
};

// Forward declarations to avoid circular dependencies
class SessionSmartCache;
class WindowsServiceManager;
class PerformanceGuardian;
class ExplorerBooster;
class IdleAffinityManager;
class MemoryOptimizer;
class InputGuardian; 
class PolicyOptimizer; // Logic for adaptive parameter tuning
class PerformanceGovernor;
class ConsequenceEvaluator;
class PredictiveModel; // Machine learning model for state prediction
class DecisionArbiter; // Logic for resolving conflicting priority requests
class Executor;
class ShadowExecutor; // Simulation Layer
class RealitySampler; // Reality Measurement Layer
class PredictionLedger; // Prediction Error Statistics
class ConfidenceTracker; // Long-term Belief Stability
class SandboxExecutor;   // Zero-Risk Authority Gate
class IntentTracker;     // Intent Persistence Gate
class OutcomeGuard;      // Reactive Rollback Guard
class AuthorityBudget;   // Cumulative Cost Limiter
class ProvenanceLedger;  // Decision Provenance
class PolicyGuard;       // Policy Boundary Contract
class ExternalVerdict;   // External Verdict Interface
class Investigator;      // The System Detective
class IpcServer;         // Secure IPC

class PManContext {
public:
    static PManContext& Get() {
        static PManContext instance;
        return instance;
    }

    // Delete copy/move to enforce singleton
    PManContext(const PManContext&) = delete;
    PManContext& operator=(const PManContext&) = delete;

    // -- App State --
    std::atomic<bool> isRunning{true};
    std::atomic<bool> reloadRequested{false};
    std::atomic<bool> servicesSuspended{false};
    std::atomic<bool> isSuspended{false};
    std::atomic<bool> isPaused{false};

    // [FIX] Restored Missing Flags
    std::atomic<bool> ignoreNonInteractive{true};
    std::atomic<bool> restoreOnExit{true};
    
    std::atomic<uint64_t> policyState{0};
    std::atomic<DWORD> lastRamCleanPid{0};

    // -- Adversarial Resilience (Fault Injection) --
    struct FaultState {
        std::atomic<bool> ledgerWriteFail{false};
        std::atomic<bool> budgetCorruption{false};
        std::atomic<bool> sandboxError{false};
        std::atomic<bool> intentInvalid{false};
        std::atomic<bool> confidenceInvalid{false};
    } fault;

    // -- Session State --
    std::atomic<DWORD> lastGamePid{0};
    std::atomic<int>   lastMode{0};
    std::atomic<std::chrono::steady_clock::time_point::rep> lastPolicyChange{0};
    std::atomic<bool> sessionLocked{false};
    std::atomic<DWORD> lockedGamePid{0};
    std::atomic<std::chrono::steady_clock::time_point::rep> lockStartTime{0};

    // -- System Capabilities (Immutable after init) --
    struct SystemState {
        OSCapabilities caps;
        CPUInfo cpu;
        DWORD physicalCoreCount{0};
        DWORD logicalCoreCount{0};
        DWORD_PTR physicalCoreMask{0};
        
        // Hybrid Core Management
        std::vector<ULONG> pCoreSets;
        std::vector<ULONG> eCoreSets;
        std::mutex cpuSetMtx;
    } sys;

    // -- Runtime Primitives (Handles & Sync) --
    struct RuntimeState {
        UniqueHandle hIocp;
        UniqueHandle hShutdownEvent; // Global stop event
        
        std::mutex shutdownMtx;
        std::condition_variable shutdownCv;
        std::atomic<int> threadCount{0};
        
        // Config reload timestamp
        std::atomic<std::chrono::steady_clock::time_point::rep> lastConfigReload{0};
        
        // Session Smart Cache (Thread-Safe Atomic Shared Pointer)
        std::atomic<std::shared_ptr<SessionSmartCache>> sessionCache;

        HPOWERNOTIFY pwr1{nullptr};
        HPOWERNOTIFY pwr2{nullptr};
        UniqueHandle hMutex;
        std::atomic<DWORD> cachedRegistryValue{0xFFFFFFFF};
        DWORD originalRegistryValue{0xFFFFFFFF};
    } runtime;

    // -- Configuration (User Settings & Lists) --
    struct ConfigState {
        // Flags & Options
        std::atomic<bool> lockPolicy{false};
        std::atomic<int>  interferenceCount{0};
        std::atomic<bool> suspendUpdatesDuringGames{false};
        std::atomic<bool> pauseIdle{false};
        std::atomic<bool> idleRevertEnabled{true};
        std::atomic<uint32_t> idleTimeoutMs{300000}; // Default 5m
        
        std::atomic<bool> responsivenessRecoveryEnabled{true};
        std::atomic<bool> recoveryPromptEnabled{true};
        std::atomic<bool> keepAwake{false};
        std::wstring iconTheme{L"Default"};

        // Process Lists
        std::shared_mutex setMtx;
        std::unordered_set<std::wstring> games;
        std::unordered_set<std::wstring> browsers;
        std::unordered_set<std::wstring> videoPlayers;
        std::unordered_set<std::wstring> gameWindows;
        std::unordered_set<std::wstring> browserWindows;
        std::unordered_set<std::wstring> customLaunchers;
        std::unordered_set<std::wstring> ignoredProcesses;
        std::unordered_set<std::wstring> oldGames;
    } conf;

    // -- Feature State (Hardware/OS Feature Availability) --
    struct FeatureState {
        // Compatibility Flags
        std::atomic<bool> isLowCoreCount{false};
        std::atomic<bool> isLowMemory{false};

        // Registry & System Features
        std::atomic<bool> memoryCompressionModified{false};
        std::atomic<DWORD> originalMemoryCompression{0xFFFFFFFF};
        std::atomic<bool> gpuSchedulingAvailable{false};
        
        // Timer Resolution
        std::atomic<ULONG> timerResolutionActive{0};
        std::atomic<ULONG> originalTimerResolution{0};

        // Memory & Latency Features
        std::atomic<bool> workingSetManagementAvailable{false};
        std::atomic<bool> dpcLatencyAvailable{false};
        std::atomic<bool> timerCoalescingAvailable{false};
        std::atomic<bool> highResTimersActive{false};
    } feat;

    // -- Process State (Hierarchy & Identity) --
    struct ProcState {
        // Identity & PID Reuse Protection
        std::mutex identityMtx;
        ProcessIdentity lastIdentity = {0, {0, 0}};
        ProcessIdentity lockedIdentity = {0, {0, 0}};

        // Hierarchy
        std::shared_mutex hierarchyMtx;
        std::unordered_map<ProcessIdentity, ProcessNode, ProcessIdentityHash> hierarchy;
        std::unordered_map<DWORD, ProcessIdentity> inheritedGamePids;

        // Resource Tracking (Working Sets)
        std::mutex workingSetMtx;
        std::unordered_map<DWORD, SIZE_T> originalWorkingSets;
        std::mutex trimTimeMtx;
        std::unordered_map<DWORD, std::chrono::steady_clock::time_point> lastTrimTimes;

        // DPC/ISR State
        std::mutex dpcStateMtx;
        std::unordered_map<DWORD, bool> processesWithBoostDisabled;
    } proc;

    // -- Network State --
    struct NetState {
        std::shared_mutex mtx;
        std::unordered_set<DWORD> activePids;
        std::atomic<NetworkState> networkState{NetworkState::Offline};
    } net;

    // -- Telemetry & Diagnostics --
    struct TelemetryState {
        MemoryTelemetry mem{};
        
        // ETW & Root Cause
        std::atomic<TRACEHANDLE> etwSession{0};
        std::atomic<uint64_t> lastEtwHeartbeat{0};
        std::atomic<double> lastDpcLatency{0.0};
    } telem;

    // -- Subsystems (Owned Singletons) --
    struct SubsystemState {
        std::unique_ptr<WindowsServiceManager> serviceMgr;
        std::unique_ptr<PerformanceGuardian>   perf;
        std::unique_ptr<ExplorerBooster>       explorer;
        std::unique_ptr<IdleAffinityManager>   idle;
        std::unique_ptr<MemoryOptimizer>       mem;
        std::unique_ptr<InputGuardian>         input; 
        std::unique_ptr<PolicyOptimizer>       optimizer; // Runtime instance of the parameter optimizer
        std::unique_ptr<PerformanceGovernor>   governor;
        std::unique_ptr<ConsequenceEvaluator>  evaluator; // Engine for calculating the cost/benefit of potential actions
        std::unique_ptr<PredictiveModel>       model;     // Active predictive model for system load
        std::unique_ptr<DecisionArbiter>       arbiter;   // Central arbiter for final decision making
        // Subsystem for safely executing and verifying actions
        std::unique_ptr<Executor>              executor;
        std::unique_ptr<ShadowExecutor>        shadow;    // Shadow Execution Layer
        std::unique_ptr<RealitySampler>        reality;   // Reality Measurement Layer
        std::unique_ptr<PredictionLedger>      ledger;    // Prediction Error Statistics
        std::unique_ptr<ConfidenceTracker>     confidence;// Long-term Belief Stability
        std::unique_ptr<SandboxExecutor>       sandbox;   // Zero-Risk Authority Gate
        std::unique_ptr<IntentTracker>         intent;    // Intent Persistence Gate
        std::unique_ptr<OutcomeGuard>          guard;     // Reactive Rollback Guard
        std::unique_ptr<AuthorityBudget>       budget;    // Authority Budget
        std::unique_ptr<ProvenanceLedger>      provenance;// Post-Hoc Justification
        std::unique_ptr<PolicyGuard>           policy;    // Policy Boundary Contract
        std::unique_ptr<ExternalVerdict>       verdict;   // External Verdict Interface
        std::unique_ptr<Investigator>          investigator; // The System Detective
        std::unique_ptr<IpcServer>             ipc;          // Secure IPC Core
    } subs;

private:
    // Defined in src/context.cpp to handle unique_ptr of incomplete types
    PManContext();
    ~PManContext();
};

#endif // PMAN_CONTEXT_H
