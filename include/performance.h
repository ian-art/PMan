#ifndef PMAN_PERFORMANCE_H
#define PMAN_PERFORMANCE_H

#include "types.h"
#include <vector>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <filesystem>

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
    uint8_t ioVoteCount = 3;  // Start with moderate confidence
    uint8_t pinVoteCount = 3;
    uint8_t memVoteCount = 3;
};

class PerformanceGuardian {
private:
    struct FrameData {
        uint64_t timestamp;
        double durationMs;
    };

    struct GameSession {
        DWORD pid;
        std::wstring exeName;
        std::deque<FrameData> frameHistory;
        uint64_t lastAnalysisTime;
        bool learningMode;
        
        // Silent Learning Engine State
        // 0=Baseline, 1=TestIOPriority, 2=TestCorePinning, 3=TestMemoryCompression, 4=Done
        int testPhase = 0; 
        std::vector<double> baselineStats; // [mean, variance, p99]
        std::vector<double> testStats;     // [mean, variance, p99]
        uint64_t testStartTime = 0;
        bool currentTestEnabled = false;   // Is optimization ON in this phase?

        // Temporary storage for multi-phase test results
        bool tempIoHelps = false;
        bool tempPinHelps = false;

        // Session Reporting
        uint64_t sessionStartTime = 0;
        uint32_t sessionStutterCount = 0;
    };

    // Root Cause Correlation
    struct SystemSnapshot {
        uint64_t timestamp;
        double bitsBandwidthMB;
        double dpcLatencyUs;
        double cpuLoad;
        double memoryPressure;
    };

    std::mutex m_mtx;
    std::unordered_map<DWORD, GameSession> m_sessions;
    std::unordered_map<std::wstring, GameProfile> m_profiles;
    std::filesystem::path m_dbPath;

    // Core Logic
    void AnalyzeStutter(GameSession& session, DWORD pid);
    void UpdateLearning(GameSession& session);
    void SaveProfile(const GameProfile& profile);
    void LoadProfiles();
    void ApplyProfile(DWORD pid, const GameProfile& profile);

    // Statistical Helpers
    std::vector<double> CalculateStats(const std::deque<FrameData>& history);
    bool IsSignificantImprovement(const std::vector<double>& baseline, const std::vector<double>& test);

    // Diagnostic Helpers
    SystemSnapshot CaptureSnapshot(DWORD pid);
    void LogStutterData(const std::wstring& exeName, const SystemSnapshot& snap);

    // Reporting Helpers
    void GenerateSessionReport(const GameSession& session);
    std::string FormatDuration(uint64_t startMs);
    std::string GetActiveOptimizations(const std::wstring& exeName);
    int CalculatePerformanceScore(const GameSession& session);

public:
    PerformanceGuardian();
    void Initialize();
    void OnGameStart(DWORD pid, const std::wstring& exeName);
    void OnGameStop(DWORD pid);
    void OnPresentEvent(DWORD pid, uint64_t timestamp);
    
    // FIX: CPU Fallback & Heartbeat for DX9 games
    void EstimateFrameTimeFromCPU(DWORD pid);
    void OnPerformanceTick();
    
    // Returns true if specific optimization is allowed based on learned profile
    bool IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature);
    
    // Emergency response
    void TriggerEmergencyBoost(DWORD pid);
};

#endif // PMAN_PERFORMANCE_H