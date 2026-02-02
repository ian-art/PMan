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

#include "brain_rl_engine.h"
#include "hands_rl_engine.h" // Phase 11: The Hands
#include "logger.h"
#include "utils.h"
#include "tweaks.h"
#include "sysinfo.h" // For GetLogPath
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <limits> // Required for std::numeric_limits
#include <pdh.h>
#include <shellapi.h>

#pragma comment(lib, "pdh.lib")

AdaptiveEngine::AdaptiveEngine() {}

void AdaptiveEngine::Initialize() {
    m_dbPath = GetLogPath() / L"profiles.bin";
    LoadProfiles();
    InitializeLearning(); // Phase 4
    Log("[ADAPTIVE] Learning Engine Initialized. CoreBrain: Online.");
    
    // Phase 10: Shadow Mode defaults to true. 
    // In production, this would be loaded from config.
    m_shadowMode = true; 
}

void AdaptiveEngine::Shutdown() {
    SaveBrain(); // Phase 8: Save Q-Tables to brain.bin
}

void AdaptiveEngine::OnSessionStart(DWORD pid, const std::wstring& exeName) {
    std::lock_guard lock(m_mtx);
    
    LearningSession session;
    session.pid = pid;
    session.exeName = exeName;
    session.lastAnalysisTime = GetTickCount64();
    session.sessionStartTime = GetTickCount64();
    session.learningMode = false;
    session.testPhase = 0;

    auto it = m_profiles.find(exeName);
    if (it != m_profiles.end()) {
        // Existing profile found
        // Adaptive Check: Re-validate every 10th session
        if (it->second.totalSessions > 0 && it->second.totalSessions % 10 == 0) {
            Log("[ADAPTIVE] Scheduled Re-evaluation for " + WideToUtf8(exeName.c_str()));
            session.learningMode = true;
        }
    } else {
        // New application: Start learning
        Log("[ADAPTIVE] New workload detected. Engaging Learning Mode.");
        session.learningMode = true;
    }
    
    m_sessions[pid] = session;
}

void AdaptiveEngine::OnSessionStop(DWORD pid) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it != m_sessions.end()) {
        // Update session count on successful completion (>1 min)
        if (GetTickCount64() - it->second.sessionStartTime > 60000) {
            auto pIt = m_profiles.find(it->second.exeName);
            if (pIt != m_profiles.end()) {
                pIt->second.totalSessions++;
                SaveProfile(pIt->second);
            }
        }
        m_sessions.erase(it);
    }
}

void AdaptiveEngine::IngestFrameData(DWORD pid, uint64_t timestamp, double durationMs) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;

    auto& hist = it->second.frameHistory;
    
    // Filter outliers (alt-tab pauses)
    if (durationMs > 0.1 && durationMs < 1000.0) {
        hist.push_back({timestamp, durationMs});
        if (hist.size() > 120) hist.pop_front();
    }
}

void AdaptiveEngine::OnPerformanceTick() {
    std::lock_guard lock(m_mtx);
    uint64_t tickStart = GetTickCount64();
    
    // 1. Budget Check (Start of tick)
    if (m_degradedMode) {
        // Attempt recovery with minimal work
        if (CheckBudget(tickStart)) return; 
    }

    // 2. Global State Capture (Phase 1)
    // We pass 0 as PID for global system state
    SystemState globalState = CaptureSystemState(0);
    
    // 3. Process Delayed Rewards (Phase 4.4)
    // Calculate global reward based on CURRENT state (result of past actions)
    double currentReward = ComputeGlobalReward(globalState);
    ProcessDelayedRewards(globalState, currentReward);

    // 4. Decision Pipeline (Phase 3)
    if (IsSafeToLearn()) {
        ActionIntent intent = ProposeAction(globalState); // Phase 6 (UCB1)
        
        // Phase 3.2: Validation
        if (!ValidateIntent(intent)) {
            // Vetoed -> Maintain
            LogTelemetry(intent, "VETOED", 0.0);
        } else {
            // Phase 2: Execution
            bool executed = false;

            if (!m_shadowMode) {
                // Phase 11: Dispatch to Executor (Wiring)
                ::ActionIntent execIntent; // Use global ActionIntent from types.h
                execIntent.action = intent.action;
                execIntent.confidence = intent.confidence;
                execIntent.timestamp = intent.timestamp;
                execIntent.nonce = tickStart;

                // The Executor performs validation, targeting, and application
                auto receipt = Executor::Get().Execute(execIntent);
                
                if (receipt) {
                    executed = true;
                    RecordActionExecution(intent.action, tickStart);
                } else {
                    LogTelemetry(intent, "EXECUTOR_REJECTED", 0.0);
                }
            } else {
                // Shadow mode: Simulate success for learning tracking
                executed = true;
            }
            
            if (executed) {
                LogTelemetry(intent, "EXECUTED", 0.0); // Reward comes later
                
                // Phase 4: Store Pending Experience
                PendingExperience pending;
                pending.stateIdx = static_cast<uint32_t>(GetStateIndex(intent.state));
                pending.action = intent.action;
                pending.tickCreated = tickStart;
                m_pendingExperiences.push_back(pending);
            }
        }
        
        // Phase 4.2: Learning Step
        UpdateQModel();
    }

    // 5. Per-Process Adaptive Logic (Legacy/Specific Optimizations)
    for (auto& pair : m_sessions) {
        LearningSession& session = pair.second;
        if (session.learningMode && !session.frameHistory.empty()) {
            if (tickStart - session.lastAnalysisTime > 2000) {
                UpdateLearning(session);
                session.lastAnalysisTime = tickStart;
            }
        }
    }

    // 6. Final Budget Check
    CheckBudget(tickStart);
}

void AdaptiveEngine::UpdateLearning(LearningSession& session) {
    if (!session.learningMode || session.testPhase > 4) return;
    
    uint64_t now = GetTickCount64();
    const uint64_t PHASE_DURATION_MS = 30000; // 30 seconds per phase
    
    if (now - session.testStartTime < 5000) return; // Buffer

    switch (session.testPhase) {
        case 0: // Baseline
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.baselineStats = CalculateStats(session.frameHistory);
                
                if (session.baselineStats[1] > 100.0) { // Unstable baseline
                     session.testStartTime = now; 
                     return; 
                }

                Log("[LEARN] Baseline captured: mean=" + std::to_string(session.baselineStats[0]) + 
                    "ms, var=" + std::to_string(session.baselineStats[1]));
                
                session.testPhase = 1;
                session.testStartTime = now;
                session.currentTestEnabled = true;
                
                // TEST 1: I/O Priority (Delegated to Executor)
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::IoPriority, 1);
            }
            break;
            
        case 1: // Test I/O
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool ioHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] I/O Priority test: " + std::string(ioHelps ? "IMPROVED" : "NO_EFFECT"));
                session.tempIoHelps = ioHelps;
                
                // Revert IO
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::IoPriority, 2);
                Sleep(1000);
                
                session.testPhase = 2;
                session.testStartTime = now;
                
                // TEST 2: Core Pinning
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::CorePinning, 1);
            }
            break;
            
        case 2: // Test Core Pinning
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool pinHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] Core Pinning test: " + std::string(pinHelps ? "IMPROVED" : "NO_EFFECT"));
                session.tempPinHelps = pinHelps;
                
                // Revert Pinning (implied normal affinity/fallback)
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::CorePinning, 2);
                Sleep(1000);
                
                session.testPhase = 3;
                session.testStartTime = now;
                
                // TEST 3: Memory Compression
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::MemoryCompression, 1);
            }
            break;
            
        case 3: // Test Memory Compression & Finalize
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool memHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] Memory Compression test: " + std::string(memHelps ? "IMPROVED" : "NO_EFFECT"));
                
                // Finalize Memory
                Executor::Get().ApplyTestProfile(session.pid, Executor::TestType::MemoryCompression, 2);
                session.testPhase = 4; // Done
                
                // Adaptive Voting Logic & RL Integration
                std::wstring name = session.exeName;
                GameProfile profile;
                
                if (m_profiles.find(name) != m_profiles.end()) {
                    profile = m_profiles[name];
                } else {
                    profile.exeName = name;
                    profile.totalSessions = 1;
                }

                auto UpdateVote = [](uint8_t& vote, bool helps) {
                    if (helps) vote = (vote >= 5) ? 5 : vote + 1;
                    else       vote = (vote <= 0) ? 0 : vote - 1;
                };

                UpdateVote(profile.ioVoteCount, session.tempIoHelps);
                UpdateVote(profile.pinVoteCount, session.tempPinHelps);
                UpdateVote(profile.memVoteCount, memHelps);

                // Threshold > 2 enables feature
                profile.useHighIo = (profile.ioVoteCount >= 2);
                profile.useCorePinning = (profile.pinVoteCount >= 2);
                profile.useMemoryCompression = (profile.memVoteCount >= 2);
                
                profile.baselineFrameTimeMs = session.baselineStats[0];
                profile.lastUpdated = now;
                
                // Calculate Reward Signal for future RL agent
                float reward = CalculateReward(session);
                
                SaveProfile(profile);
                
                Log("[ADAPT] Profile updated for " + WideToUtf8(name.c_str()) + 
                    " | IO:" + std::to_string(profile.ioVoteCount) + 
                    " Pin:" + std::to_string(profile.pinVoteCount) + 
                    " Mem:" + std::to_string(profile.memVoteCount) + 
                    " | Reward: " + std::to_string(reward));
            }
            break;
    }
}

std::vector<double> AdaptiveEngine::CalculateStats(const std::deque<FrameData>& history) {
    std::vector<double> stats(3, 0.0);
    if (history.empty()) return stats;
    
    std::vector<double> sortedDurations;
    sortedDurations.reserve(history.size());
    
    double sum = 0;
    for (const auto& f : history) {
        sortedDurations.push_back(f.durationMs);
        sum += f.durationMs;
    }
    
    stats[0] = sum / sortedDurations.size(); // Mean
    
    double sqSum = 0;
    for (double d : sortedDurations) {
        sqSum += (d - stats[0]) * (d - stats[0]);
    }
    stats[1] = sqSum / sortedDurations.size(); // Variance
    
    std::sort(sortedDurations.begin(), sortedDurations.end());
    size_t idx = static_cast<size_t>(sortedDurations.size() * 0.99);
    if (idx >= sortedDurations.size()) idx = sortedDurations.size() - 1;
    stats[2] = sortedDurations[idx]; // 99th Percentile
    
    return stats;
}

bool AdaptiveEngine::IsSignificantImprovement(const std::vector<double>& baseline,
                                              const std::vector<double>& test) {
    if (baseline.size() < 3 || test.size() < 3) return false;
    bool varImproved = test[1] < (baseline[1] * 0.90);
    bool tailImproved = test[2] < (baseline[2] * 0.95);
    bool meanImproved = test[0] < (baseline[0] * 0.95);
    return varImproved || tailImproved || meanImproved;
}

bool AdaptiveEngine::IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature) {
    std::lock_guard lock(m_mtx);
    if (m_profiles.find(exeName) != m_profiles.end()) {
        const auto& p = m_profiles[exeName];
        if (feature == "io") return p.useHighIo;
        if (feature == "pin") return p.useCorePinning;
        if (feature == "mem") return p.useMemoryCompression;
    }
    return true; 
}

GameProfile AdaptiveEngine::GetProfile(const std::wstring& exeName) {
    std::lock_guard lock(m_mtx);
    if (m_profiles.find(exeName) != m_profiles.end()) {
        return m_profiles[exeName];
    }
    return GameProfile{exeName};
}

bool AdaptiveEngine::IsLearningActive(DWORD pid) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it != m_sessions.end()) return it->second.learningMode;
    return false;
}

void AdaptiveEngine::LoadProfiles() {
    std::ifstream f(m_dbPath, std::ios::binary);
    if (!f) return;
    
    uint32_t magic = 0;
    uint32_t version = 0;
    f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    f.read(reinterpret_cast<char*>(&version), sizeof(version));

    if (magic != 0x504D414E) return;

    size_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    if (count > 100000) return;

    for(size_t i=0; i<count; ++i) {
        GameProfile p;
        size_t nameLen = 0;
        f.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        if (nameLen > 0) {
            std::vector<wchar_t> buf(nameLen + 1);
            f.read(reinterpret_cast<char*>(buf.data()), nameLen * sizeof(wchar_t));
            p.exeName = buf.data();
        }
        f.read(reinterpret_cast<char*>(&p.useHighIo), sizeof(bool));
        f.read(reinterpret_cast<char*>(&p.useCorePinning), sizeof(bool));
        f.read(reinterpret_cast<char*>(&p.useMemoryCompression), sizeof(bool));
        f.read(reinterpret_cast<char*>(&p.useTimerCoalescing), sizeof(bool));
        f.read(reinterpret_cast<char*>(&p.baselineFrameTimeMs), sizeof(double));
        f.read(reinterpret_cast<char*>(&p.lastUpdated), sizeof(uint64_t));
        
        if (f.peek() != EOF) {
            f.read(reinterpret_cast<char*>(&p.totalSessions), sizeof(uint32_t));
            f.read(reinterpret_cast<char*>(&p.ioVoteCount), sizeof(uint8_t));
            f.read(reinterpret_cast<char*>(&p.pinVoteCount), sizeof(uint8_t));
            f.read(reinterpret_cast<char*>(&p.memVoteCount), sizeof(uint8_t));
        }

        m_profiles[p.exeName] = p;
    }
}

void AdaptiveEngine::SaveProfile(const GameProfile& profile) {
    m_profiles[profile.exeName] = profile;
    
    std::filesystem::path tmpPath = m_dbPath;
    tmpPath += L".tmp";

    {
        std::ofstream f(tmpPath, std::ios::binary | std::ios::trunc);
        if (!f) return;
        
        uint32_t magic = 0x504D414E; // 'PMAN'
        uint32_t version = 1;
        f.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        f.write(reinterpret_cast<const char*>(&version), sizeof(version));

        size_t count = m_profiles.size();
        f.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        for(const auto& [name, p] : m_profiles) {
            size_t nameLen = p.exeName.length();
            f.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
            f.write(reinterpret_cast<const char*>(p.exeName.c_str()), nameLen * sizeof(wchar_t));
            f.write(reinterpret_cast<const char*>(&p.useHighIo), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useCorePinning), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useMemoryCompression), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useTimerCoalescing), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.baselineFrameTimeMs), sizeof(double));
            f.write(reinterpret_cast<const char*>(&p.lastUpdated), sizeof(uint64_t));
            
            f.write(reinterpret_cast<const char*>(&p.totalSessions), sizeof(uint32_t));
            f.write(reinterpret_cast<const char*>(&p.ioVoteCount), sizeof(uint8_t));
            f.write(reinterpret_cast<const char*>(&p.pinVoteCount), sizeof(uint8_t));
            f.write(reinterpret_cast<const char*>(&p.memVoteCount), sizeof(uint8_t));
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmpPath, m_dbPath, ec);
    if (ec) {
        std::filesystem::remove(m_dbPath, ec);
        std::filesystem::rename(tmpPath, m_dbPath, ec);
    }
}

float AdaptiveEngine::CalculateReward(const LearningSession& session) {
    // Basic RL Reward Function: (Baseline - NewMean) / Variance
    if (session.baselineStats.empty() || session.testStats.empty()) return 0.0f;
    float improvement = (float)(session.baselineStats[0] - session.testStats[0]);
    return improvement;
}

// --------------------------------------------------------------------------
// PHASE 1.2: Quantization Functions (Hard Thresholds)
// --------------------------------------------------------------------------

uint32_t AdaptiveEngine::QuantizeCpu(double loadPercent) {
    if (loadPercent < 10.0) return 0; // Idle
    if (loadPercent < 30.0) return 1; // Light
    if (loadPercent < 50.0) return 2; // Moderate
    if (loadPercent < 70.0) return 3; // Busy
    if (loadPercent < 90.0) return 4; // High
    return 5;                         // Critical
}

uint32_t AdaptiveEngine::QuantizeDiskIo(double activeTime) {
    if (activeTime < 0.1) return 0; // Idle
    if (activeTime < 0.3) return 1; // Low
    if (activeTime < 0.6) return 2; // Moderate
    if (activeTime < 0.9) return 3; // High
    return 4;                       // Thrashing
}

uint32_t AdaptiveEngine::QuantizeMemory(double loadPercent) {
    if (loadPercent < 60.0) return 0; // Healthy
    if (loadPercent < 80.0) return 1; // Moderate
    if (loadPercent < 90.0) return 2; // High
    return 3;                         // Critical
}

uint32_t AdaptiveEngine::QuantizeUserIdle(uint64_t idleSeconds) {
    if (idleSeconds < 5)   return 0; // Active
    if (idleSeconds < 60)  return 1; // Brief Pause
    if (idleSeconds < 300) return 2; // Away
    return 3;                        // Long Idle
}

uint32_t AdaptiveEngine::QuantizeThermal(int tempCelsius) {
    if (tempCelsius < 50) return 0; // Cool
    if (tempCelsius < 70) return 1; // Warm
    if (tempCelsius < 85) return 2; // Hot
    return 3;                       // Throttling
}

// --------------------------------------------------------------------------
// PHASE 1.3: Generalization Hash
// --------------------------------------------------------------------------

uint32_t AdaptiveEngine::ComputeGeneralizationHash(SystemState state) {
    SystemState generalized = state;
    
    // Rule 1: Ignore Thermal State (local variance shouldn't split policy)
    generalized.bits.ThermalState = 0;
    
    // Rule 2: Collapse Process Categories (Interactive vs Background)
    // 00 (Game) & 01 (Desktop) -> 0
    // 10 (Work) & 11 (Critical) -> 1
    generalized.bits.ProcessCategory = (state.bits.ProcessCategory <= 1) ? 0 : 1;
    
    // Rule 3: Retain Pressure + Latency Sensitivity
    // (Preserved implicitly by copy)
    
    return generalized.raw;
}

SystemState AdaptiveEngine::CaptureSystemState(DWORD pid) {
    SystemState state = {0};

    // 1. CPU Load (Bits 0-2)
    double cpuLoad = GetCpuLoad(); // From utils.h
    state.bits.CpuLoad = QuantizeCpu(cpuLoad);

    // 2. Memory Pressure (Bits 6-7)
    MEMORYSTATUSEX memStatus = { sizeof(MEMORYSTATUSEX) };
    if (GlobalMemoryStatusEx(&memStatus)) {
        state.bits.MemoryPressure = QuantizeMemory(memStatus.dwMemoryLoad);
    }

    // 3. Disk IO Pressure (Bits 3-5) via PDH
    static PDH_HQUERY hQuery = nullptr;
    static PDH_HCOUNTER hDiskCounter = nullptr;
    static bool pdhInitialized = false;

    if (!pdhInitialized) {
        if (PdhOpenQueryW(nullptr, 0, &hQuery) == ERROR_SUCCESS) {
            // Monitor Total Disk Time as a proxy for pressure
            if (PdhAddCounterW(hQuery, L"\\PhysicalDisk(_Total)\\% Disk Time", 0, &hDiskCounter) == ERROR_SUCCESS) {
                PdhCollectQueryData(hQuery); // Initial seed
                pdhInitialized = true;
            }
        }
    }

    double diskVal = 0.0;
    if (pdhInitialized && hDiskCounter) {
        if (PdhCollectQueryData(hQuery) == ERROR_SUCCESS) {
            PDH_FMT_COUNTERVALUE displayValue;
            if (PdhGetFormattedCounterValue(hDiskCounter, PDH_FMT_DOUBLE, nullptr, &displayValue) == ERROR_SUCCESS) {
                diskVal = displayValue.doubleValue;
                // Clamp to 0.0 - 1.0 range approximation (PDH can return >100%)
                if (diskVal > 100.0) diskVal = 100.0;
                diskVal /= 100.0; 
            }
        }
    }
    state.bits.DiskIoPressure = QuantizeDiskIo(diskVal);

    // 4. User Idle Time (Bits 8-9)
    LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
    uint64_t idleSec = 0;
    if (GetLastInputInfo(&lii)) {
        idleSec = (GetTickCount() - lii.dwTime) / 1000;
    }
    state.bits.UserIdleTime = QuantizeUserIdle(idleSec);

    // 5. Thermal State (Bits 12-13)
    // Stub: Requires WMI/Bios calls which are slow. Assuming Cool (0) unless critical.
    state.bits.ThermalState = 0; 

    // 6. Process Category (Bits 10-11)
    if (pid != 0) {
        // Heuristic Classification
        HWND hForeground = GetForegroundWindow();
        DWORD fgPid = 0;
        GetWindowThreadProcessId(hForeground, &fgPid);
        
        bool isForeground = (fgPid == pid);
        
        // Improve: Basic Criticality Check (DWM + Self)
        // This resolves the warning by using the variable and adding safety logic.
        bool isCritical = (pid == GetDwmProcessId()) || (pid == GetCurrentProcessId()); 
        
        // Check "types.h" for ProcessCategory enum definition logic
        // 00=Game, 01=Desktop, 10=Work, 11=System
        
        if (isCritical) {
             state.bits.ProcessCategory = 0b11; // System_Critical
        } else if (isForeground) {
             // If we had IsGameMode() or similar check, we'd return Interactive_Game
             state.bits.ProcessCategory = 0b01; // Interactive_Desktop
        } else {
             state.bits.ProcessCategory = 0b10; // Background_Work
        }
    }

    return state;
}

// --------------------------------------------------------------------------
// PHASE 2.3: Action Cooldowns
// --------------------------------------------------------------------------

uint64_t AdaptiveEngine::GetActionCooldownDuration(BrainAction action) {
    // Minimums defined in Roadmap Phase 2.3
    switch (action) {
        case BrainAction::Throttle_Aggressive: return 30000; // 30s (Safe upper bound of 15-30s)
        case BrainAction::Suspend_Services:    return 60000; // 60s
        case BrainAction::Optimize_Memory:     return 60000; // 60s
        case BrainAction::Release_Pressure:    return 5000;  // 5s
        case BrainAction::Throttle_Mild:       return 5000;  // 5s (Implied hysteresis)
        case BrainAction::Maintain:            return 0;
        default:                               return 0;
    }
}

bool AdaptiveEngine::IsActionReady(BrainAction action, uint64_t now) const {
    size_t idx = static_cast<size_t>(action);
    if (idx >= ACTION_COUNT) return false;

    uint64_t lastTime = m_lastActionTime[idx];
    if (lastTime == 0) return true; // Never executed

    uint64_t cooldown = GetActionCooldownDuration(action);
    return (now - lastTime) >= cooldown;
}

void AdaptiveEngine::RecordActionExecution(BrainAction action, uint64_t now) {
    size_t idx = static_cast<size_t>(action);
    if (idx < ACTION_COUNT) {
        m_lastActionTime[idx] = now;
    }
}

// --------------------------------------------------------------------------
// PHASE 3: Decision Pipeline
// --------------------------------------------------------------------------

bool AdaptiveEngine::ValidateIntent(ActionIntent& intent) {
    // 1. Hard Veto: Always allow Maintain
    if (intent.action == BrainAction::Maintain) return true;

    uint64_t now = GetTickCount64();

    // 2. Cooldown Check (Phase 2.3)
    if (!IsActionReady(intent.action, now)) {
        Log("[VETO] Cooldown active for action " + std::to_string((int)intent.action));
        intent.action = BrainAction::Maintain;
        return false;
    }

    // 3. Confidence Check (Phase 6.2 - Forward Compat)
    // confidence = (Q_best - Q_second) / ... logic handled in learning core, 
    // but strict gate applied here.
    if (intent.confidence < 0.6) {
        // Log("[VETO] Low confidence: " + std::to_string(intent.confidence));
        intent.action = BrainAction::Maintain;
        return false;
    }

    // 4. Session Safety (Phase 3.2.1)
    // We cannot trust Session 0 (Services) to be interactive
    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        if (sessionId == 0 && intent.action != BrainAction::Suspend_Services) {
            // If WE are in session 0, we must be very careful about assuming foreground
            // This check might need to be against the Target PID, not us.
            // Assuming ValidateIntent is called in context of a target decision:
            // TODO: Pass Target PID to ValidateIntent for full Session 0 check
        }
    }

    // 5. External Arbitration (Phase 3.2.2)
    if (IsExternalGovernorActive()) {
        Log("[VETO] External Governor Active (Game Mode / Lasso). Yielding.");
        intent.action = BrainAction::Maintain;
        return false;
    }

    return true;
}

bool AdaptiveEngine::IsExternalGovernorActive() {
    static uint64_t lastCheck = 0;
    static bool cachedResult = false;
    uint64_t now = GetTickCount64();

    // Cache results for 5 seconds to avoid high-frequency API polling
    if (now - lastCheck < 5000) {
        return cachedResult;
    }
    lastCheck = now;
    cachedResult = false;

    // Check 1: Windows Game Mode / Fullscreen D3D
    // SHQueryUserNotificationState is a lightweight way to detect "Game Mode" or "Presentation Mode"
    QUERY_USER_NOTIFICATION_STATE quns;
    if (SHQueryUserNotificationState(&quns) == S_OK) {
        if (quns == QUNS_RUNNING_D3D_FULL_SCREEN || quns == QUNS_PRESENTATION_MODE) {
            // Windows is already managing resources for a game/presentation
            cachedResult = true;
            return true;
        }
    }

    // Check 2: Conflicting Optimization Tools
    // We check if "ProcessLasso.exe" is running.
    // Using utils.h helper
    if (GetProcessIdByName(L"ProcessLasso.exe") != 0) {
        cachedResult = true;
        return true;
    }
    
    // Add other tools as needed (e.g., "MSIAfterburner.exe")

    return cachedResult;
}

// --------------------------------------------------------------------------
// PHASE 4: Learning Core
// --------------------------------------------------------------------------

size_t AdaptiveEngine::GetStateIndex(SystemState state) {
    // Pack 32-bit SystemState into 13-bit dense index
    // Layout: [Cpu:3][Disk:3][Mem:2][Idle:2][Cat:1][Net:1][Lat:1]
    
    // 1. Collapse ProcessCategory (2 bits -> 1 bit)
    // 00(Game)|01(Desktop) -> 0, 10(Work)|11(Critical) -> 1
    uint32_t cat = (state.bits.ProcessCategory <= 1) ? 0 : 1;

    size_t idx = 0;
    idx |= (state.bits.CpuLoad & 0b111);             // Bits 0-2
    idx |= (state.bits.DiskIoPressure & 0b111) << 3; // Bits 3-5
    idx |= (state.bits.MemoryPressure & 0b11)  << 6; // Bits 6-7
    idx |= (state.bits.UserIdleTime & 0b11)    << 8; // Bits 8-9
    idx |= (cat & 0b1)                         << 10; // Bit  10
    idx |= (state.bits.NetworkMetered & 0b1)   << 11; // Bit  11
    idx |= (state.bits.LatencySensitiveStream & 0b1) << 12; // Bit 12
    
    return idx & (STATE_COUNT - 1); // Safety mask
}

void AdaptiveEngine::InitializeLearning() {
    // One-time allocation (Phase 4.1: No heap churn during runtime)
    m_qTableA.resize(STATE_COUNT);
    m_qTableB.resize(STATE_COUNT);
    m_visitCounts.resize(STATE_COUNT);
    m_replayBuffer.resize(REPLAY_BUFFER_SIZE);

    // Phase 8: Try to load existing brain
    if (LoadBrain()) {
        Log("[PERSISTENCE] Brain loaded successfully.");
        return;
    }

    // Phase 4.5: Cold Start Seeding (Only if load failed)
    for (size_t s = 0; s < STATE_COUNT; ++s) {
        for (size_t a = 0; a < ACTION_COUNT; ++a) {
            BrainAction action = static_cast<BrainAction>(a);
            double initialQ = 0.0;

            // Reconstruct partial state bits to check constraints
            uint32_t cat = (s >> 10) & 0b1; 
            
            // Rule: Game + Throttle = Strongly Negative
            if (cat == 0) { // Interactive/Game
                if (action == BrainAction::Throttle_Aggressive || 
                    action == BrainAction::Throttle_Mild) {
                    initialQ = -1000.0;
                }
            }

            // Rule: System Critical + Suspend = Forbidden (handled by Validator, but seed negative)
            // Note: We collapsed categories, so '1' includes SystemCritical.
            // Safety: Start conservative.
            if (cat == 1 && action == BrainAction::Suspend_Services) {
                initialQ = -500.0;
            }
            
            m_qTableA[s][a] = initialQ;
            m_qTableB[s][a] = initialQ;
        }
    }
    
    Log("[CORE] Learning initialized. Double Q-Tables seeded.");
}

void AdaptiveEngine::StoreExperience(const Experience& exp) {
    m_replayBuffer[m_replayHead] = exp;
    m_replayHead = (m_replayHead + 1) % REPLAY_BUFFER_SIZE;
    if (m_replayHead == 0) m_replayFilled = true;
}

void AdaptiveEngine::ProcessDelayedRewards(SystemState currentState, double currentReward) {
    // Phase 4.4: Delayed Rewards
    // This allows us to attribute an action taken T-2 ticks ago to the reward received now.
    
    auto it = m_pendingExperiences.begin();
    while (it != m_pendingExperiences.end()) {
        // Check if enough time has passed (Phase 4.4)
        // Note: Assuming ~2000ms per tick.
        if (GetTickCount64() - it->tickCreated >= (REWARD_DELAY_TICKS * 2000)) { 
            
            // Construct finalized experience
            Experience exp;
            exp.stateIdx = it->stateIdx;
            exp.action = it->action;
            exp.reward = currentReward; 
            // Explicit cast safe due to STATE_BITS = 13 (max value 8191)
            exp.nextStateIdx = static_cast<uint32_t>(GetStateIndex(currentState));
            
            // Phase 7: Panic Mode Check
            // If we are consistently getting punished (-5.0 or worse), something is wrong.
            if (currentReward <= -5.0) {
                m_consecutiveNegativeRewards++;
                if (m_consecutiveNegativeRewards >= 5) {
                    m_panicMode = true;
                    Log("[FAILSAFE] PANIC MODE ACTIVATED. Sustained negative rewards detected.");
                }
            } else if (currentReward > 0.0) {
                // Reset counter on success
                m_consecutiveNegativeRewards = 0;
            }

            if (IsSafeToLearn()) {
                StoreExperience(exp);
            }
            
            it = m_pendingExperiences.erase(it);
        } else {
            ++it;
        }
    }
}

void AdaptiveEngine::UpdateQModel() {
    // Phase 4.2: Double Q-Learning
    if (!m_replayFilled && m_replayHead < 50) return; // Wait for data

    // Sample random batch
    // Optimization: Small batch to bound CPU usage
    const int BATCH_SIZE = 8;
    const double ALPHA = 0.1; // Learning rate
    const double GAMMA = 0.9; // Discount factor

    for (int i = 0; i < BATCH_SIZE; ++i) {
        // Random sample (Phase 4.3)
        size_t idx = rand() % (m_replayFilled ? REPLAY_BUFFER_SIZE : m_replayHead);
        const Experience& e = m_replayBuffer[idx];

        // Double Q Update Logic
        if (rand() % 2 == 0) {
            // Update A using B
            // max_a Q_A(next, a)
            double maxQ = -99999.0;
            size_t bestAction = 0;
            for(size_t a=0; a<ACTION_COUNT; ++a) {
                if (m_qTableA[e.nextStateIdx][a] > maxQ) {
                    maxQ = m_qTableA[e.nextStateIdx][a];
                    bestAction = a;
                }
            }
            
            double target = e.reward + GAMMA * m_qTableB[e.nextStateIdx][bestAction];
            size_t actIdx = static_cast<size_t>(e.action);
            m_qTableA[e.stateIdx][actIdx] += ALPHA * (target - m_qTableA[e.stateIdx][actIdx]);
        } else {
            // Update B using A
            double maxQ = -99999.0;
            size_t bestAction = 0;
            for(size_t a=0; a<ACTION_COUNT; ++a) {
                if (m_qTableB[e.nextStateIdx][a] > maxQ) {
                    maxQ = m_qTableB[e.nextStateIdx][a];
                    bestAction = a;
                }
            }

            double target = e.reward + GAMMA * m_qTableA[e.nextStateIdx][bestAction];
            size_t actIdx = static_cast<size_t>(e.action);
            m_qTableB[e.stateIdx][actIdx] += ALPHA * (target - m_qTableB[e.stateIdx][actIdx]);
        }
    }
}

// --------------------------------------------------------------------------
// PHASE 5: Reward Function
// --------------------------------------------------------------------------

double AdaptiveEngine::ComputeGlobalReward(SystemState state) {
    // Base survival reward (System is alive)
    double reward = 1.0; 

    // Extract components for readability
    uint32_t cpu = state.bits.CpuLoad;        // 0-5
    uint32_t disk = state.bits.DiskIoPressure;// 0-4
    uint32_t mem = state.bits.MemoryPressure; // 0-3
    uint32_t therm = state.bits.ThermalState; // 0-3
    uint32_t idle = state.bits.UserIdleTime;  // 0-3
    bool latSens = state.bits.LatencySensitiveStream;

    // 1. Stability Penalties (Non-linear)
    if (cpu >= 4)   reward -= (cpu - 2) * 1.5; // Busy/High CPU hurts
    if (mem >= 3)   reward -= 5.0;             // Critical memory is dangerous
    if (therm >= 2) reward -= (therm * 4.0);   // Thermal throttling is a failure

    // 2. Latency/Interactive Penalties (The "Human Factor")
    // Humans feel lag more than smoothness.
    // If user is active (Idle < 2) or watching a stream, lag is unacceptable.
    bool userActive = (idle < 2) || latSens;
    double lagPenaltyMult = userActive ? 5.0 : 1.0;

    // 3. Disk I/O (Context-Sensitive)
    // Phase 5.1: Suppress I/O penalty if we just triggered it ourselves via Memory Optimization
    if (!IsInGraceWindow()) {
        if (disk >= 3) reward -= (disk * 2.0) * lagPenaltyMult;
    }

    // 4. Critical UX Failures (Hard penalties)
    if (userActive && (cpu >= 5 || disk >= 4)) {
        reward -= 20.0; // Stutter detected during interaction
    }

    return reward;
}

bool AdaptiveEngine::IsInGraceWindow() const {
    // Phase 5.1: Optimize_Memory Side-Effect Model
    // We expect IO spikes after emptying the working set.
    // Suppress penalties for 2 ticks (approx 4-5 seconds).
    
    uint64_t lastMemOpt = m_lastActionTime[static_cast<size_t>(BrainAction::Optimize_Memory)];
    if (lastMemOpt == 0) return false;

    uint64_t now = GetTickCount64();
    const uint64_t GRACE_MS = 4500; // 2 ticks * ~2.2s buffer
    
    return (now - lastMemOpt) < GRACE_MS;
}

// --------------------------------------------------------------------------
// PHASE 6: Exploration & Confidence
// --------------------------------------------------------------------------

AdaptiveEngine::ActionIntent AdaptiveEngine::ProposeAction(SystemState state) {
    size_t stateIdx = GetStateIndex(state);
    uint32_t totalVisits = 0;
    
    // Calculate total visits for this state N(s)
    for (uint32_t c : m_visitCounts[stateIdx]) totalVisits += c;

    // 1. UCB1 Selection (Exploration)
    BrainAction bestAction = BrainAction::Maintain;
    double bestScore = -std::numeric_limits<double>::infinity();
    
    // Exploration constant (c) - tunable, usually sqrt(2) or 1.0
    const double C_EXPLORE = 1.0; 

    for (size_t a = 0; a < ACTION_COUNT; ++a) {
        double score;
        uint32_t n = m_visitCounts[stateIdx][a];

        if (n == 0) {
            // Unvisited actions get infinite priority (Cold Start)
            score = std::numeric_limits<double>::infinity();
        } else {
            // UCB1 = Q_mean + c * sqrt(log(Total) / n)
            double qMean = (m_qTableA[stateIdx][a] + m_qTableB[stateIdx][a]) / 2.0;
            score = qMean + C_EXPLORE * std::sqrt(std::log((double)totalVisits) / n);
        }

        if (score > bestScore) {
            bestScore = score;
            bestAction = static_cast<BrainAction>(a);
        }
    }

    // 2. Confidence Calculation (Phase 6.2)
    // Based on pure Q-values (Exploitation view), not UCB scores
    double qBest = -std::numeric_limits<double>::infinity();
    double qSecond = -std::numeric_limits<double>::infinity();

    for (size_t a = 0; a < ACTION_COUNT; ++a) {
        double qVal = (m_qTableA[stateIdx][a] + m_qTableB[stateIdx][a]) / 2.0;
        if (qVal > qBest) {
            qSecond = qBest;
            qBest = qVal;
        } else if (qVal > qSecond) {
            qSecond = qVal;
        }
    }

    double confidence = 0.0;
    const double EPSILON = 1e-6;
    if (std::abs(qBest) > EPSILON) {
        confidence = (qBest - qSecond) / (std::abs(qBest) + EPSILON);
    }

    // 3. Construct Intent
    ActionIntent intent;
    intent.action = bestAction;
    intent.confidence = confidence;
    intent.state = state;
    intent.timestamp = GetTickCount64();

    // Side-effect: Increment visit count for the chosen action
    // This prevents sampling the same "Infinite" action repeatedly if execution is delayed
    m_visitCounts[stateIdx][static_cast<size_t>(bestAction)]++;

    return intent;
}

// --------------------------------------------------------------------------
// PHASE 7: Failsafes
// --------------------------------------------------------------------------

bool AdaptiveEngine::IsSafeToLearn() const {
    if (m_panicMode) return false;

    // TODO: Add check for Windows Update service status (wuauserv)
    // TODO: Add check for TiWorker.exe or TrustedInstaller.exe
    
    // For now, checking IsExternalGovernorActive (Game Mode) is a good proxy 
    // for "Do Not Disturb", but strictly we need specific service checks here.
    
    return true;
}

// --------------------------------------------------------------------------
// PHASE 8: Persistence
// --------------------------------------------------------------------------

struct BrainHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t stateCount;
    uint32_t actionCount;
};

void AdaptiveEngine::SaveBrain() {
    std::filesystem::path brainPath = GetLogPath() / L"brain.bin";
    std::ofstream f(brainPath, std::ios::binary | std::ios::trunc);
    if (!f) return;

    BrainHeader header;
    header.magic = 0x42524149; // 'BRAI'
    header.version = 1;
    header.stateCount = static_cast<uint32_t>(STATE_COUNT);
    header.actionCount = static_cast<uint32_t>(ACTION_COUNT);

    f.write(reinterpret_cast<const char*>(&header), sizeof(header));

    // Write Tables
    size_t tableSize = STATE_COUNT * sizeof(std::array<double, ACTION_COUNT>);
    f.write(reinterpret_cast<const char*>(m_qTableA.data()), tableSize);
    f.write(reinterpret_cast<const char*>(m_qTableB.data()), tableSize);
    
    // Write Visits
    size_t visitSize = STATE_COUNT * sizeof(std::array<uint32_t, ACTION_COUNT>);
    f.write(reinterpret_cast<const char*>(m_visitCounts.data()), visitSize);
    
    Log("[PERSISTENCE] Brain saved.");
}

bool AdaptiveEngine::LoadBrain() {
    std::filesystem::path brainPath = GetLogPath() / L"brain.bin";
    std::ifstream f(brainPath, std::ios::binary);
    if (!f) return false;

    BrainHeader header;
    f.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (header.magic != 0x42524149) return false;
    if (header.stateCount != STATE_COUNT) return false; // Schema mismatch
    if (header.actionCount != ACTION_COUNT) return false;

    size_t tableSize = STATE_COUNT * sizeof(std::array<double, ACTION_COUNT>);
    f.read(reinterpret_cast<char*>(m_qTableA.data()), tableSize);
    f.read(reinterpret_cast<char*>(m_qTableB.data()), tableSize);

    size_t visitSize = STATE_COUNT * sizeof(std::array<uint32_t, ACTION_COUNT>);
    f.read(reinterpret_cast<char*>(m_visitCounts.data()), visitSize);

    return !!f;
}

// --------------------------------------------------------------------------
// PHASE 9: Telemetry
// --------------------------------------------------------------------------

void AdaptiveEngine::LogTelemetry(const ActionIntent& intent, const std::string& status, double reward) {
    // Structured Log Format for analysis
    std::string log = "[BRAIN] ";
    log += "Tick=" + std::to_string(intent.timestamp) + " ";
    log += "State=" + std::to_string(intent.state.raw) + " ";
    log += "Action=" + std::to_string((int)intent.action) + " ";
    log += "Conf=" + std::to_string(intent.confidence) + " ";
    log += "Reward=" + std::to_string(reward) + " ";
    log += "Status=" + status;
    
    if (m_shadowMode) log += " (SHADOW)";
    if (m_degradedMode) log += " (DEGRADED)";
    
    Log(log);
}

// --------------------------------------------------------------------------
// PHASE 10: Integration & Budgeting
// --------------------------------------------------------------------------

bool AdaptiveEngine::CheckBudget(uint64_t tickStart) {
    uint64_t now = GetTickCount64();
    uint64_t elapsed = now - tickStart;
    m_lastTickDuration = elapsed;

    const uint64_t BUDGET_MS = 50; // Phase 10.1 Hard Limit

    if (elapsed > BUDGET_MS) {
        Log("[BUDGET] Tick exceeded budget: " + std::to_string(elapsed) + "ms. Entering Degraded Mode.");
        m_degradedMode = true;
        return false;
    }
    
    // Auto-recover from degraded mode if fast enough
    if (elapsed < (BUDGET_MS / 2)) {
        m_degradedMode = false;
    }

    return true;
}
