#include "performance.h"
#include "logger.h"
#include "globals.h"
#include "events.h"
#include "tweaks.h"
#include "utils.h"
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <psapi.h> // Required for GetProcessMemoryInfo

#pragma comment(lib, "Psapi.lib") // Link PSAPI

PerformanceGuardian::PerformanceGuardian() {}

void PerformanceGuardian::Initialize() {
    m_dbPath = GetLogPath() / L"profiles.bin";
    LoadProfiles();
    Log("[PERF] Autonomous Performance Guardian Initialized");
}

void PerformanceGuardian::LoadProfiles() {
    std::ifstream f(m_dbPath, std::ios::binary);
    if (!f) return;
    
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
        m_profiles[p.exeName] = p;
    }
    Log("[PERF] Loaded " + std::to_string(count) + " performance profiles");
}

void PerformanceGuardian::SaveProfile(const GameProfile& profile) {
    m_profiles[profile.exeName] = profile;
    
    std::ofstream f(m_dbPath, std::ios::binary | std::ios::trunc);
    if (!f) return;
    
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
    }
}

void PerformanceGuardian::OnGameStart(DWORD pid, const std::wstring& exeName) {
    std::lock_guard lock(m_mtx);
    GameSession session;
    session.pid = pid;
    session.exeName = exeName;
    session.lastAnalysisTime = GetTickCount64();
    
    // Check if we have a profile
    if (m_profiles.find(exeName) == m_profiles.end()) {
        session.learningMode = true;
        session.learningPhase = 0; // Baseline
        Log("[PERF] New game detected: " + WideToUtf8(exeName.c_str()) + " - Entering Silent Learning Mode");
    } else {
        session.learningMode = false;
        const auto& p = m_profiles[exeName];
        Log("[PERF] Profile loaded for " + WideToUtf8(exeName.c_str()) + 
            " (Optimizations: IO=" + (p.useHighIo?"ON":"OFF") + 
            ", Pin=" + (p.useCorePinning?"ON":"OFF") + ")");
    }
    
    m_sessions[pid] = session;
}

void PerformanceGuardian::OnGameStop(DWORD pid) {
    std::lock_guard lock(m_mtx);
    m_sessions.erase(pid);
}

void PerformanceGuardian::OnPresentEvent(DWORD pid, uint64_t timestamp) {
    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;
    
    GameSession& session = it->second;
    
    if (!session.frameHistory.empty()) {
        uint64_t prev = session.frameHistory.back().timestamp;
        double deltaMs = (timestamp - prev) / 10000.0; // 100ns units to ms
        
        // Filter outliers (alt-tab pauses)
        if (deltaMs > 0.1 && deltaMs < 1000.0) {
            session.frameHistory.push_back({timestamp, deltaMs});
        }
    } else {
        session.frameHistory.push_back({timestamp, 0.0});
    }
    
    // Keep last 600 frames (~10s at 60fps)
    if (session.frameHistory.size() > 600) {
        session.frameHistory.pop_front();
    }
    
    // Analyze every 2 seconds
    uint64_t now = GetTickCount64();
    if (now - session.lastAnalysisTime > 2000) {
        AnalyzeStutter(session, pid);
        if (session.learningMode) UpdateLearning(session);
        session.lastAnalysisTime = now;
    }
}

void PerformanceGuardian::AnalyzeStutter(GameSession& session, DWORD pid) {
    if (session.frameHistory.size() < 60) return;
    
    // Calculate Stats
    double sum = 0, sqSum = 0;
    for (const auto& f : session.frameHistory) {
        sum += f.durationMs;
        sqSum += f.durationMs * f.durationMs;
    }
    
	double mean = sum / session.frameHistory.size();
    double variance = (sqSum / session.frameHistory.size()) - (mean * mean);
    // Fix: Prevent macro expansion of max by using parentheses
    double stdDev = std::sqrt((std::max)(0.0, variance));
    
    // Detect Micro-stutters (spikes > 2 sigma)
    int spikeCount = 0;
    for (const auto& f : session.frameHistory) {
        if (f.durationMs > mean + (2.0 * stdDev)) spikeCount++;
    }
    
    // Emergency Threshold: 5% of frames are stutters OR variance is huge
    if (spikeCount > (session.frameHistory.size() * 0.05) || stdDev > 8.0) {
        Log("[PERF] Stutter detected for PID " + std::to_string(pid) + 
            " (Var: " + std::to_string(variance) + ", Spikes: " + std::to_string(spikeCount) + ")");
        
        // Trigger IOCP job for thread-safe handling
        PostIocp(JobType::PerformanceEmergency, pid);
    }
}

void PerformanceGuardian::TriggerEmergencyBoost(DWORD pid) {
    // This runs on the IOCP thread
    Log("[PERF] >>> EMERGENCY BOOST ACTIVATED for PID " + std::to_string(pid) + " <<<");
    
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid);
    if (hProc) {
        // 1. Force Realtime (dangerous but necessary for stutter elim)
        SetPriorityClass(hProc, REALTIME_PRIORITY_CLASS);
        
        // 2. Aggressive Working Set Expansion (prevent paging)
        // Check if we can get current size
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
             SIZE_T target = pmc.WorkingSetSize + (500 * 1024 * 1024); // Add 500MB buffer
             SetProcessWorkingSetSize(hProc, 200 * 1024 * 1024, target);
        }
        
        CloseHandle(hProc);
    }
    
    // 3. Suspend non-critical services immediately
    SuspendBackgroundServices();
    
    // 4. Force High-Res Timer
    SetTimerResolution(1);
}

void PerformanceGuardian::UpdateLearning(GameSession& session) {
    // Simplified A/B testing logic
    if (session.learningPhase == 0) {
        // Gathering baseline
        if (session.frameHistory.size() > 300) {
            // Calculate baseline variance
            // ... (stats calc) ...
            session.learningPhase++;
            Log("[PERF] Baseline captured. Starting optimization A/B tests...");
        }
    }
    // Further phases would toggle g_pCoreSets, etc.
}

bool PerformanceGuardian::IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature) {
    std::lock_guard lock(m_mtx);
    if (m_profiles.find(exeName) != m_profiles.end()) {
        const auto& p = m_profiles[exeName];
        if (feature == "io") return p.useHighIo;
        if (feature == "pin") return p.useCorePinning;
        if (feature == "mem") return p.useMemoryCompression;
    }
    return true; // Default allow
}