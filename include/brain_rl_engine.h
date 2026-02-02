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

// BRAIN REINFORCEMENT LEARNING ENGINE

#ifndef PMAN_BRAIN_RL_ENGINE_H
#define PMAN_BRAIN_RL_ENGINE_H

#include "types.h"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <filesystem>
#include <array>

// Phase 1.1: Canonical SystemState (Bit-Packed, Deterministic)
union SystemState {
    uint32_t raw;
    struct {
        uint32_t CpuLoad : 3;
        uint32_t DiskIoPressure : 3;
        uint32_t MemoryPressure : 2;
        uint32_t UserIdleTime : 2;
        uint32_t ProcessCategory : 2;
        uint32_t ThermalState : 2;
        uint32_t NetworkMetered : 1;
        uint32_t LatencySensitiveStream : 1;
        uint32_t Reserved : 16;
    } bits;

    bool operator==(const SystemState& other) const { return raw == other.raw; }
};
static_assert(sizeof(SystemState) == 4, "State must be 32-bit");

// Core optimization profile structure
// Migrated from performance.h to serve as the output policy for the engine
struct GameProfile {
    std::wstring exeName;
    bool useHighIo;
    bool useCorePinning;
    bool useMemoryCompression;
    bool useTimerCoalescing;
    double baselineFrameTimeMs;
    uint64_t lastUpdated;

    // Adaptive Evolution State
    uint32_t totalSessions = 0;
    uint8_t ioVoteCount = 3;  
    uint8_t pinVoteCount = 3;
    uint8_t memVoteCount = 3;
};

class AdaptiveEngine {
public:
    struct FrameData {
        uint64_t timestamp;
        double durationMs;
    };

    AdaptiveEngine();
    ~AdaptiveEngine(); // [FIX] Added Destructor Declaration
    void Initialize();
    void Shutdown();

    // Session Lifecycle Hooks (Called by PerformanceGuardian)
    void OnSessionStart(DWORD pid, const std::wstring& exeName);
    void OnSessionStop(DWORD pid);
    void IngestFrameData(DWORD pid, uint64_t timestamp, double durationMs);
    
    // Main Driver Loop
    void OnPerformanceTick(); 

    // Decision & Policy Queries
    bool IsLearningActive(DWORD pid);
    bool IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature);
    GameProfile GetProfile(const std::wstring& exeName);

    // Phase 1: State Model & Input Pipeline
    SystemState CaptureSystemState(DWORD pid);

    // Phase 1.2: Quantization Functions
    static uint32_t QuantizeCpu(double loadPercent);
    static uint32_t QuantizeDiskIo(double activeTime);
    static uint32_t QuantizeMemory(double loadPercent);
    static uint32_t QuantizeUserIdle(uint64_t idleSeconds);
    static uint32_t QuantizeThermal(int tempCelsius);

    // Phase 1.3: Generalization Hash
    static uint32_t ComputeGeneralizationHash(SystemState state);

    // Phase 3.1: Action Intent Structure
    struct ActionIntent {
        BrainAction action;
        double confidence;
        SystemState state;
        uint64_t timestamp;
    };

    // Phase 2.3: Action Cooldown Queries
    bool IsActionReady(BrainAction action, uint64_t now) const;
    void RecordActionExecution(BrainAction action, uint64_t now);
    static uint64_t GetActionCooldownDuration(BrainAction action);

    // Phase 3: Decision Pipeline (Policy != Execution)
    // Returns true if the intent is safe to execute. If false, intent is mutated to Maintain.
    bool ValidateIntent(ActionIntent& intent);
    
    // Phase 3.2.2: External Optimizer Arbitration
    // Returns true if an external governor (Game Mode, Process Lasso) is active.
    bool IsExternalGovernorActive();

    // Phase 4: Learning Core
    static constexpr size_t STATE_BITS = 13; // Packed dense state (CPU 3 + Disk 3 + Mem 2 + Idle 2 + Cat 1 + Net 1 + Lat 1)
    static constexpr size_t STATE_COUNT = 1 << STATE_BITS;
    static constexpr size_t REPLAY_BUFFER_SIZE = 1000;
    static constexpr size_t REWARD_DELAY_TICKS = 2;
    
    // Dense State Indexer
    static size_t GetStateIndex(SystemState state);

    struct Experience {
        uint32_t stateIdx;
        BrainAction action;
        double reward;
        uint32_t nextStateIdx;
    };

    struct PendingExperience {
        uint32_t stateIdx;
        BrainAction action;
        uint64_t tickCreated;
    };

    // Phase 4.1: Double Q-Tables (Heap allocated once to prevent stack overflow)
    // Using vector as flat 2D array [State][Action]
    std::vector<std::array<double, ACTION_COUNT>> m_qTableA;
    std::vector<std::array<double, ACTION_COUNT>> m_qTableB;
    
    // Phase 6.1: Visit Counts for UCB1
    std::vector<std::array<uint32_t, ACTION_COUNT>> m_visitCounts;

    // Phase 4.3: Experience Replay
    std::vector<Experience> m_replayBuffer;
    size_t m_replayHead = 0;
    bool m_replayFilled = false;

    // Phase 4.4: Delayed Rewards
    std::deque<PendingExperience> m_pendingExperiences;

    // Phase 2.3: Cooldown State
    std::array<uint64_t, ACTION_COUNT> m_lastActionTime = {0};

    // Core Learning Methods
    void InitializeLearning();
    void UpdateQModel(); // Runs the Double-Q learning step
    void StoreExperience(const Experience& exp);
    void ProcessDelayedRewards(SystemState currentState, double currentReward);

    // Phase 5: Reward Function (The Conscience)
    double ComputeGlobalReward(SystemState state);

    // Phase 5.1: Post-Action Grace Windows
    bool IsInGraceWindow() const;

    // Phase 6: Exploration & Confidence
    // Generates an ActionIntent using UCB1 exploration and calculates confidence.
    ActionIntent ProposeAction(SystemState state);

    // Phase 7: Failsafes
    bool m_panicMode = false;
    int m_consecutiveNegativeRewards = 0;
    bool IsSafeToLearn() const; // Checks Windows Update, Driver Install, Panic

    // Phase 8: Persistence
    void SaveBrain();
    bool LoadBrain();

    // Phase 9: Telemetry
    void LogTelemetry(const ActionIntent& intent, const std::string& status, double reward = 0.0);

    // Phase 10: Integration & Budgeting
    bool m_shadowMode = true; // Default to Shadow Mode (No execution)
    bool m_degradedMode = false; // Triggered by budget violations
    uint64_t m_lastTickDuration = 0;
    
    // Phase 10.1: Runtime Budget Check
    // Returns false if budget exceeded
    bool CheckBudget(uint64_t tickStart);

    // [ARCH-FIX] Phase 12: Deterministic Policy Layer
    // RL is demoted to "Tuner". These structures hold the actual control logic.
    struct PolicyConfig {
        uint32_t cpuThreshold = 4; // Default: High (Quantized 0-5)
        uint32_t memThreshold = 2; // Default: High (Quantized 0-3)
        uint32_t diskThreshold = 3; // Default: High (Quantized 0-4)
        bool allowThrottle = true;
        bool allowTrim = true;
    } m_policy;

    void UpdatePolicyParameters(BrainAction rlHint);
    BrainAction ResolveDeterministicRule(SystemState state);

private:
    struct LearningSession {
        DWORD pid;
        std::wstring exeName;
        std::deque<FrameData> frameHistory;
        uint64_t lastAnalysisTime;
        bool learningMode;
        
        // A/B Testing State Machine
        // 0=Baseline, 1=TestIOPriority, 2=TestCorePinning, 3=TestMemoryCompression, 4=Done
        int testPhase = 0; 
        std::vector<double> baselineStats; // [mean, variance, p99]
        std::vector<double> testStats;
        uint64_t testStartTime = 0;
        bool currentTestEnabled = false;

        // Temporary Voting Results
        bool tempIoHelps = false;
        bool tempPinHelps = false;
        
        uint64_t sessionStartTime = 0;
    };

    std::mutex m_mtx;
    std::unordered_map<DWORD, LearningSession> m_sessions;
    std::unordered_map<std::wstring, GameProfile> m_profiles;
    std::filesystem::path m_dbPath;

    // Persistence
    void LoadProfiles();
    void SaveProfile(const GameProfile& profile);

    // Core Analysis Logic
    void UpdateLearning(LearningSession& session);
    std::vector<double> CalculateStats(const std::deque<FrameData>& history);
    bool IsSignificantImprovement(const std::vector<double>& baseline, const std::vector<double>& test);
    
    // Helper to calculate RL Reward Signal (Stub for future implementation)
    float CalculateReward(const LearningSession& session);
};

#endif // PMAN_BRAIN_RL_ENGINE_H
