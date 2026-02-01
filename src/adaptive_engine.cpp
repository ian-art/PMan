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

#include "adaptive_engine.h"
#include "logger.h"
#include "utils.h"
#include "tweaks.h"
#include "sysinfo.h" // For GetLogPath
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>

AdaptiveEngine::AdaptiveEngine() {}

void AdaptiveEngine::Initialize() {
    m_dbPath = GetLogPath() / L"profiles.bin";
    LoadProfiles();
    Log("[ADAPTIVE] Learning Engine Initialized. Reinforcement Controller: Standing By.");
}

void AdaptiveEngine::Shutdown() {
    // Save state if needed
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
    uint64_t now = GetTickCount64();

    for (auto& pair : m_sessions) {
        LearningSession& session = pair.second;
        
        if (session.learningMode && !session.frameHistory.empty()) {
            // Drive learning loop every 2 seconds
            if (now - session.lastAnalysisTime > 2000) {
                UpdateLearning(session);
                session.lastAnalysisTime = now;
            }
        }
    }
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
                
                // TEST 1: I/O Priority
                SetProcessIoPriority(session.pid, 1);
            }
            break;
            
        case 1: // Test I/O
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool ioHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] I/O Priority test: " + std::string(ioHelps ? "IMPROVED" : "NO_EFFECT"));
                session.tempIoHelps = ioHelps;
                
                SetProcessIoPriority(session.pid, 2); 
                Sleep(1000);
                
                session.testPhase = 2;
                session.testStartTime = now;
                
                // TEST 2: Core Pinning
                SetHybridCoreAffinity(session.pid, 1);
            }
            break;
            
        case 2: // Test Core Pinning
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool pinHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] Core Pinning test: " + std::string(pinHelps ? "IMPROVED" : "NO_EFFECT"));
                session.tempPinHelps = pinHelps;
                
                SetProcessAffinity(session.pid, 2);
                Sleep(1000);
                
                session.testPhase = 3;
                session.testStartTime = now;
                
                // TEST 3: Memory Compression
                SetMemoryCompression(1);
            }
            break;
            
        case 3: // Test Memory Compression & Finalize
            if (now - session.testStartTime > PHASE_DURATION_MS) {
                session.testStats = CalculateStats(session.frameHistory);
                bool memHelps = IsSignificantImprovement(session.baselineStats, session.testStats);
                
                Log("[LEARN] Memory Compression test: " + std::string(memHelps ? "IMPROVED" : "NO_EFFECT"));
                
                SetMemoryCompression(2);
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
                rlState.rewardSignal = CalculateReward(session);
                
                SaveProfile(profile);
                
                Log("[ADAPT] Profile updated for " + WideToUtf8(name.c_str()) + 
                    " | IO:" + std::to_string(profile.ioVoteCount) + 
                    " Pin:" + std::to_string(profile.pinVoteCount) + 
                    " Mem:" + std::to_string(profile.memVoteCount) + 
                    " | Reward: " + std::to_string(rlState.rewardSignal));
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
