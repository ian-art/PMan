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
        int learningPhase; // 0=Baseline, 1=TestA, 2=TestB
        double baselineVariance;
    };

    std::mutex m_mtx;
    std::unordered_map<DWORD, GameSession> m_sessions;
    std::unordered_map<std::wstring, GameProfile> m_profiles;
    std::filesystem::path m_dbPath;

    void AnalyzeStutter(GameSession& session, DWORD pid);
    void UpdateLearning(GameSession& session);
    void SaveProfile(const GameProfile& profile);
    void LoadProfiles();

public:
    PerformanceGuardian();
    void Initialize();
    void OnGameStart(DWORD pid, const std::wstring& exeName);
    void OnGameStop(DWORD pid);
    void OnPresentEvent(DWORD pid, uint64_t timestamp);
    
    // Returns true if specific optimization is allowed based on learned profile
    bool IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature);
    
    // Emergency response
    void TriggerEmergencyBoost(DWORD pid);
};

#endif // PMAN_PERFORMANCE_H