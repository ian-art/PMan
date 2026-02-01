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

#ifndef PMAN_ADAPTIVE_ENGINE_H
#define PMAN_ADAPTIVE_ENGINE_H

#include "types.h"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <filesystem>

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

    // Future: Adaptive OS-Level Reinforcement Controller
    // Reserved for Q-Learning/PPO state vectors
    struct ReinforcementController {
        float rewardSignal;
        float penaltySignal;
        uint64_t lastStateVector;
        // Placeholder for neural weights or Q-Table
    } rlState;

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

#endif // PMAN_ADAPTIVE_ENGINE_H
