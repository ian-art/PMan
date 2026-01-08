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

#include "performance.h"
#include "logger.h"
#include "globals.h"
#include "events.h"
#include "tweaks.h"
#include "utils.h"
#include "services.h" // For GetBitsBandwidth
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <psapi.h> // Required for GetProcessMemoryInfo

#pragma comment(lib, "Psapi.lib") // Link PSAPI

// Helper to get precise process creation time for identity validation
static uint64_t GetProcessCreationTimeHelper(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;
    FILETIME c, e, k, u;
    uint64_t res = 0;
    if (GetProcessTimes(hProc, &c, &e, &k, &u)) {
        res = (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    }
    CloseHandle(hProc);
    return res;
}

PerformanceGuardian::PerformanceGuardian() {}

void PerformanceGuardian::Initialize() {
    m_dbPath = GetLogPath() / L"profiles.bin";
    LoadProfiles();
    Log("[PERF] Autonomous Performance Guardian Initialized");
}

void PerformanceGuardian::LoadProfiles() {
    std::ifstream f(m_dbPath, std::ios::binary);
    if (!f) return;
    
    // FIX: Verify Header Magic and Version to prevent reading corrupt data
    uint32_t magic = 0;
    uint32_t version = 0;
    f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    f.read(reinterpret_cast<char*>(&version), sizeof(version));

    if (magic != 0x504D414E) { // 'PMAN'
        Log("[PERF] Corrupt or invalid profile database. Resetting.");
        f.close();
        return; 
    }

    size_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    
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
        
        // Read Adaptive Voting Data
        // Check if file has more data (backward compatibility)
        if (f.peek() != EOF) {
            f.read(reinterpret_cast<char*>(&p.totalSessions), sizeof(uint32_t));
            f.read(reinterpret_cast<char*>(&p.ioVoteCount), sizeof(uint8_t));
            f.read(reinterpret_cast<char*>(&p.pinVoteCount), sizeof(uint8_t));
            f.read(reinterpret_cast<char*>(&p.memVoteCount), sizeof(uint8_t));
        } else {
            // Default values for old profiles
            p.totalSessions = 0;
            p.ioVoteCount = 3;
            p.pinVoteCount = 3;
            p.memVoteCount = 3;
        }

        m_profiles[p.exeName] = p;
    }
    Log("[PERF] Loaded " + std::to_string(count) + " performance profiles");
}

void PerformanceGuardian::SaveProfile(const GameProfile& profile) {
    m_profiles[profile.exeName] = profile;
    
    std::ofstream f(m_dbPath, std::ios::binary | std::ios::trunc);
    if (!f) return;
    
    // FIX: Write Header Magic and Version
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
        
        // Write Adaptive Voting Data
        f.write(reinterpret_cast<const char*>(&p.totalSessions), sizeof(uint32_t));
        f.write(reinterpret_cast<const char*>(&p.ioVoteCount), sizeof(uint8_t));
        f.write(reinterpret_cast<const char*>(&p.pinVoteCount), sizeof(uint8_t));
        f.write(reinterpret_cast<const char*>(&p.memVoteCount), sizeof(uint8_t));
    }
}

void PerformanceGuardian::OnGameStart(DWORD pid, const std::wstring& exeName) {
    std::lock_guard lock(m_mtx);
    GameSession session;
    session.pid = pid;
	session.exeName = exeName;
    session.lastAnalysisTime = GetTickCount64();
    session.sessionStartTime = GetTickCount64();
    session.sessionStutterCount = 0;
    session.creationTime = GetProcessCreationTimeHelper(pid);
    
    // Check if we have a profile
    auto it = m_profiles.find(exeName);
    if (it != m_profiles.end()) {
        // Existing profile found
        GameProfile& profile = it->second;
        profile.totalSessions++;

        // Adaptive Check: Re-validate every 10th session
        if (profile.totalSessions % 10 == 0) {
            Log("[PERF] Adaptive Check: Re-evaluating profile for " + WideToUtf8(exeName.c_str()));
            session.learningMode = true;
            session.testPhase = 0;
            // Don't apply optimizations yet; we want a fresh baseline
        } else {
            // Standard Run: Apply known profile
            Log("[PERF] Applying stable profile for " + WideToUtf8(exeName.c_str()));
            ApplyProfile(pid, profile);
            session.learningMode = false;
        }
        
        SaveProfile(profile);
    } else {
        // Unknown game, start learning
        Log("[PERF] New game detected. Starting Silent Learning Mode...");
        session.learningMode = true;
        session.testPhase = 0; // Baseline Capture
    }
    
    m_sessions[pid] = session;
}

void PerformanceGuardian::ApplyProfile(DWORD pid, const GameProfile& profile) {
    if (profile.useHighIo) SetProcessIoPriority(pid, 1);
    if (profile.useCorePinning) SetHybridCoreAffinity(pid, 1);
    if (profile.useMemoryCompression) SetMemoryCompression(1);
    if (profile.useTimerCoalescing) SetTimerCoalescingControl(1);
}

// NOTE: Caller must hold m_mtx
void PerformanceGuardian::EstimateFrameTimeFromCPU(DWORD pid) {
    // REMOVED std::lock_guard to prevent deadlock (caller holds lock)
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;
    
    GameSession& session = it->second;
    
    // FIX: Allow fallback if data is stale (>150ms), not just if empty
    // This ensures continuous fallback updates if ETW stops
    if (!session.frameHistory.empty()) {
        uint64_t lastFrameTime = session.frameHistory.back().timestamp;
        uint64_t now100ns = GetTickCount64() * 10000;
        if ((now100ns - lastFrameTime) < 1500000) return; // Data is fresh (<150ms), skip CPU fallback
    }
    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;
    
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(hProc, &creation, &exit, &kernel, &user)) {
        CloseHandle(hProc);
        return;
    }
    CloseHandle(hProc);
    
	// FIX: Use shared helper
    uint64_t totalCpuTime100ns = FileTimeToULL(kernel) + FileTimeToULL(user);
    uint64_t now = GetTickCount64();
    
    // Fix: Use per-session tracking instead of static maps
    if (session.lastCpuTimestamp != 0) {
        uint64_t deltaCpu = totalCpuTime100ns - session.lastCpuTime;
        uint64_t deltaTime = now - session.lastCpuTimestamp;
        
		if (deltaTime > 0) {
            // CORRECT FORMULA: CPU usage per frame, not total CPU time
            double cpuTimePerFrame = (deltaCpu / 10000.0) / (static_cast<double>(deltaTime) / 16.67);  // ms of CPU per 16.67ms frame
            double estimatedFrameTime = 16.67 * (cpuTimePerFrame / 100.0);  // Scale by CPU usage
            
            // If CPU usage is low (<50%), assume GPU-bound and cap at 33ms (30 FPS)
            if (cpuTimePerFrame < 50.0) {
                estimatedFrameTime = 33.33;  // GPU-bound games typically 30 FPS min
            }

            // If CPU usage is very high (>150%), assume 60 FPS target
            if (cpuTimePerFrame > 150.0) {
                estimatedFrameTime = 16.67;
            }

            if (estimatedFrameTime < 5.0) estimatedFrameTime = 5.0;
			if (estimatedFrameTime > 100.0) estimatedFrameTime = 100.0;
            
            // Fix: Silence debug log for dormant wrappers (0% CPU) to prevent spam
            // The actual game process running as a child will have its own session/logs.
            /*
            static uint32_t lastLog = 0;
            if (GetTickCount() - lastLog > 5000) {
                Log("[PERF-FALLBACK] PID " + std::to_string(pid) + " using CPU estimation: " + 
                    std::to_string(estimatedFrameTime) + "ms (CPU: " + 
                    std::to_string(cpuTimePerFrame) + "%)");
                lastLog = GetTickCount();
            }
            */

			// Add synthetic frame data
            session.frameHistory.push_back({now * 10000, estimatedFrameTime});
            if (session.frameHistory.size() > 120) session.frameHistory.pop_front();
        }
    }
	session.lastCpuTime = totalCpuTime100ns;
    session.lastCpuTimestamp = now;
}

void PerformanceGuardian::OnPerformanceTick() {
    if (g_isSuspended.load()) return;
    std::lock_guard lock(m_mtx);
    uint64_t now = GetTickCount64();

    for (auto& pair : m_sessions) {
        GameSession& session = pair.second;
        
        // 1. Force Fallback if ETW is silent
        // If history is empty OR last frame is older than 1 second
        bool isSilent = session.frameHistory.empty() || 
                       (now * 10000 - session.frameHistory.back().timestamp > 10000000); 

		if (isSilent) {
            EstimateFrameTimeFromCPU(session.pid);
        }

        // 2. Drive the Learning Loop manually
        if (now - session.lastAnalysisTime > 2000) {
            // CRITICAL FIX: Validate Process Identity before analysis
            // If the PID was reused, this prevents analyzing mixed/garbage data
            uint64_t currentCreation = GetProcessCreationTimeHelper(session.pid);
            if (currentCreation != 0 && session.creationTime != 0 && currentCreation != session.creationTime) {
                Log("[PERF] PID Reuse detected for " + std::to_string(session.pid) + " (Zombie Session). Resetting.");
                session.frameHistory.clear();
                session.creationTime = currentCreation;
                // Don't analyze this tick, wait for fresh data
                session.lastAnalysisTime = now;
                continue;
            }

            if (!session.frameHistory.empty()) {
                AnalyzeStutter(session, session.pid);
                if (session.learningMode) UpdateLearning(session);
                session.lastAnalysisTime = now;
            }
        }
    }
}

void PerformanceGuardian::OnGameStop(DWORD pid) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it != m_sessions.end()) {
        GameSession& session = it->second;
        
        //Generate Post-Session Report
        // Only report if session lasted longer than 1 minute to avoid noise
        if (GetTickCount64() - session.sessionStartTime > 60000) {
            GenerateSessionReport(session);
        }

        // Revert any persistent changes (like affinity)
        SetProcessAffinity(pid, 2); 
        SetProcessIoPriority(pid, 2);
        SetMemoryCompression(2);
        
        m_sessions.erase(it);
    }
}

void PerformanceGuardian::OnPresentEvent(DWORD pid, uint64_t timestamp) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;
    
	GameSession& session = it->second;
    
    if (!session.frameHistory.empty() && session.frameHistory.back().durationMs > 0.0) {
        uint64_t prev = session.frameHistory.back().timestamp;
        double deltaMs = (timestamp - prev) / 10000.0; // 100ns units to ms
        
        // Filter outliers (alt-tab pauses)
        if (deltaMs > 0.1 && deltaMs < 1000.0) {
            session.frameHistory.push_back({timestamp, deltaMs});
            
            // Diagnostic logging for C&C3 verification
            static int frameCount = 0;
            if (++frameCount % 300 == 0) {
                 Log("[PERF-DEBUG] Captured " + std::to_string(frameCount) + " frames for " + WideToUtf8(session.exeName.c_str()));
            }
        }
    } else {
        session.frameHistory.push_back({timestamp, 0.0});
    }
    
	if (session.frameHistory.size() > 120) {
        session.frameHistory.pop_front();
    }
    
    // [OPTIMIZATION] Removed synchronous AnalyzeStutter call.
    // Analysis is now fully offloaded to OnPerformanceTick() to keep the Present path (ETW) wait-free.
}

void PerformanceGuardian::AnalyzeStutter(GameSession& session, DWORD pid) {
    if (session.frameHistory.size() < 60) return;
    
    // Calculate Stats
	std::vector<double> stats = CalculateStats(session.frameHistory);
    double mean = stats[0];
    double variance = stats[1];
    double stdDev = std::sqrt((std::max)(0.0, variance));
    
    // Detect Micro-stutters (spikes > 2 sigma)
    int spikeCount = 0;
    for (const auto& f : session.frameHistory) {
        if (f.durationMs > mean + (2.0 * stdDev)) spikeCount++;
    }
    
    // Emergency Threshold: 5% of frames are stutters OR variance is huge
    if (spikeCount > (session.frameHistory.size() * 0.05) || stdDev > 8.0) {
        session.sessionStutterCount++; // Track

        // Capture system snapshot
        SystemSnapshot snapshot = CaptureSnapshot(pid);
        LogStutterData(session.exeName, snapshot);

        Log("[PERF] Stutter detected for PID " + std::to_string(pid) + 
            " (Var: " + std::to_string(variance) + ", Spikes: " + std::to_string(spikeCount) + ")");
        
        // Check correlations
        if (snapshot.bitsBandwidthMB > 1.0) {
            Log("[STUTTER] Likely caused by BITS/Windows Update background download");
        }
        if (snapshot.dpcLatencyUs > 1000.0) {
            Log("[STUTTER] Likely caused by high DPC latency (Driver/System interrupt)");
        }
        if (snapshot.cpuLoad > 95.0) {
            Log("[STUTTER] Likely caused by total CPU saturation");
        }
        
        // Trigger IOCP job for thread-safe handling
        PostIocp(JobType::PerformanceEmergency, pid);
    }
}

PerformanceGuardian::SystemSnapshot PerformanceGuardian::CaptureSnapshot(DWORD pid) {
    SystemSnapshot snap = {};
    snap.timestamp = GetTickCount64();

    // ENHANCEMENT: Verify process life
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return snap;
    CloseHandle(hProc);

    // 1. Check BITS bandwidth (Using new class method)
    if (g_servicesSuspended.load()) {
        snap.bitsBandwidthMB = 0.0;
    } else {
        snap.bitsBandwidthMB = g_serviceManager.GetBitsBandwidthMBps();
    }

    // 2. DPC Latency (From 95th percentile ring buffer)
    snap.dpcLatencyUs = g_lastDpcLatency.load(std::memory_order_relaxed);

    // 3. CPU Load (From Utils)
    snap.cpuLoad = GetCpuLoad();

    // 4. Memory Pressure
    MEMORYSTATUSEX ms = { sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms)) {
        snap.memoryPressure = static_cast<double>(ms.dwMemoryLoad);
    }

    return snap;
}

void PerformanceGuardian::LogStutterData(const std::wstring& exeName, const SystemSnapshot& snap) {
    std::string msg = "[DIAGNOSTIC] Snapshot for " + WideToUtf8(exeName.c_str()) + " | ";
    msg += "BITS: " + std::to_string(snap.bitsBandwidthMB) + " MB/s | ";
    msg += "DPC: " + std::to_string(snap.dpcLatencyUs) + " us | ";
    msg += "CPU: " + std::to_string(snap.cpuLoad) + "%";
    Log(msg);
}

void PerformanceGuardian::TriggerEmergencyBoost(DWORD pid) {
    // This runs on the IOCP thread
    Log("[PERF] >>> EMERGENCY BOOST ACTIVATED for PID " + std::to_string(pid) + " <<<");
    
	HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid);
    if (hProc) {
        // Fix: Use HIGH instead of REALTIME to prevent system lockup
        SetPriorityClass(hProc, HIGH_PRIORITY_CLASS);
        
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
             SIZE_T target = pmc.WorkingSetSize + (500 * 1024 * 1024); // Add 500MB buffer
             SetProcessWorkingSetSize(hProc, 200 * 1024 * 1024, target);
        }
        CloseHandle(hProc);
    }
    
    SuspendBackgroundServices();
    SetTimerResolution(1);
}

void PerformanceGuardian::UpdateLearning(GameSession& session) {
    if (!session.learningMode || session.testPhase > 4) return;
    
    uint64_t now = GetTickCount64();
    
    // FIX: Fallback to CPU estimation if ETW fails (for >5s with no frames)
    if (session.frameHistory.empty() && (now - session.sessionStartTime) > 5000) {
        EstimateFrameTimeFromCPU(session.pid);
    }
    
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
                
                // Adaptive Voting Logic
                std::wstring name = session.exeName;
                GameProfile profile;
                
                if (m_profiles.find(name) != m_profiles.end()) {
                    profile = m_profiles[name];
                } else {
                    profile.exeName = name;
                    profile.totalSessions = 1;
                    profile.ioVoteCount = 3;
                    profile.pinVoteCount = 3;
                    profile.memVoteCount = 3;
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
                
                SaveProfile(profile);
                
                Log("[ADAPT] Profile updated for " + WideToUtf8(name.c_str()) + 
                    " | IO:" + std::to_string(profile.ioVoteCount) + 
                    " Pin:" + std::to_string(profile.pinVoteCount) + 
                    " Mem:" + std::to_string(profile.memVoteCount));
            }
            break;
    }
}

std::vector<double> PerformanceGuardian::CalculateStats(const std::deque<FrameData>& history) {
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

bool PerformanceGuardian::IsSignificantImprovement(const std::vector<double>& baseline,
                                                   const std::vector<double>& test) {
    if (baseline.size() < 3 || test.size() < 3) return false;
    bool varImproved = test[1] < (baseline[1] * 0.90);
    bool tailImproved = test[2] < (baseline[2] * 0.95);
    bool meanImproved = test[0] < (baseline[0] * 0.95);
    return varImproved || tailImproved || meanImproved;
}

bool PerformanceGuardian::IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature) {
    std::lock_guard lock(m_mtx);
    if (m_profiles.find(exeName) != m_profiles.end()) {
        const auto& p = m_profiles[exeName];
        if (feature == "io") return p.useHighIo;
        if (feature == "pin") return p.useCorePinning;
        if (feature == "mem") return p.useMemoryCompression;
    }
    return true; 
}

// User Transparency Dashboard

void PerformanceGuardian::GenerateSessionReport(const GameSession& session) {
    std::string report = "\n==========================================\n";
    report += "       GAMING SESSION PERFORMANCE REPORT      \n";
    report += "==========================================\n";
    
    report += "Game: " + WideToUtf8(session.exeName.c_str()) + "\n";
    report += "Duration: " + FormatDuration(session.sessionStartTime) + "\n";
    
    bool hasFrameData = !session.frameHistory.empty();
    bool hasBaselineData = !session.baselineStats.empty();
    
    if (!hasFrameData && !hasBaselineData) {
        report += "\nWARNING: NO PERFORMANCE DATA CAPTURED\n";
        report += "Reason: ETW Present events not detected (DX9/Vulkan/OpenGL)\n";
        report += "Troubleshooting: CPU Fallback logic may be disabled or blocked.\n\n";
    }

    if (session.learningMode) {
        report += "Status: LEARNING MODE (Calibrating System)\n";
        report += "Note: Optimizations were toggled for testing.\n";
    } else {
        report += "Status: OPTIMIZED\n";
        report += "Active Tweaks: " + GetActiveOptimizations(session.exeName) + "\n";
    }

    double avgFrameTime = 0.0;
    std::string dataSource = "Unknown";
    
    if (hasBaselineData) {
        avgFrameTime = session.baselineStats[0];
        dataSource = "Baseline (ETW)";
    } else if (hasFrameData) {
        // Fallback calculation
        std::vector<double> currentStats = const_cast<PerformanceGuardian*>(this)->CalculateStats(session.frameHistory);
        if (!currentStats.empty()) {
            avgFrameTime = currentStats[0];
            dataSource = "Session Average (Fallback)";
        }
    }

    if (avgFrameTime > 0.0) {
        report += "Avg Frame Time: " + std::to_string(avgFrameTime) + " ms (" + dataSource + ")\n";
        report += "Equivalent FPS: " + std::to_string(static_cast<int>(1000.0 / avgFrameTime)) + " FPS\n";
    } else {
        report += "Avg Frame Time: N/A\n";
    }
    
    report += "Stutter Events Detected: " + std::to_string(session.sessionStutterCount) + "\n";
    report += "Stability Score: " + std::to_string(CalculatePerformanceScore(session)) + "/100\n";
    report += "==========================================\n";

    Log(report);

	std::filesystem::path reportPath = GetLogPath() / "last_session_report.txt";

    std::ofstream file(reportPath, std::ios::trunc);
    if (file.is_open()) {
        file << report;
    }
}

std::string PerformanceGuardian::FormatDuration(uint64_t startMs) {
    uint64_t duration = GetTickCount64() - startMs;
    uint64_t seconds = duration / 1000;
    uint64_t minutes = seconds / 60;
    uint64_t hours = minutes / 60;
    
    std::string res = "";
    if (hours > 0) res += std::to_string(hours) + "h ";
    if (minutes > 0) res += std::to_string(minutes % 60) + "m ";
    res += std::to_string(seconds % 60) + "s";
    return res;
}

std::string PerformanceGuardian::GetActiveOptimizations(const std::wstring& exeName) {
    auto it = m_profiles.find(exeName);
    if (it == m_profiles.end()) return "None";

    const GameProfile& p = it->second;
    std::vector<std::string> opts;
    
    if (p.useHighIo) opts.push_back("High I/O Priority");
    if (p.useCorePinning) opts.push_back("Hybrid Core Pinning");
    if (p.useMemoryCompression) opts.push_back("RAM Compression");
    if (p.useTimerCoalescing) opts.push_back("Timer Coalescing");
    
    if (opts.empty()) return "None (Baseline is optimal)";
    
    std::string result;
    for (size_t i = 0; i < opts.size(); ++i) {
        result += opts[i];
        if (i < opts.size() - 1) result += ", ";
    }
    return result;
}

int PerformanceGuardian::CalculatePerformanceScore(const GameSession& session) {
    int score = 100;
    
    // Penalize for stutters
    score -= (session.sessionStutterCount * 5);
    
    // Penalize for variance
    if (!session.baselineStats.empty() && session.baselineStats.size() >= 2) {
        double variance = session.baselineStats[1];
        if (variance > 50.0) score -= 10;
        if (variance > 100.0) score -= 10;
    }
    
    if (score < 0) score = 0;
    return score;
}
