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

#ifndef PMAN_PERFORMANCE_H
#define PMAN_PERFORMANCE_H

#include "types.h"
#include <unordered_map>
#include <string>
#include <mutex>
#include <unordered_map>
#include <filesystem>
#include <deque>
#include <vector>
#include <memory> // Required for std::shared_ptr

// Forward declarations for RAII Guards
class PowerSchemeGuard;
class VisualsSuspend;
class CacheLimiter;
class ServiceSuspensionGuard;
class InputModeGuard;
class AudioModeGuard;

// #include "policy_optimizer.h"

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

		// Session Reporting
        uint64_t sessionStartTime = 0;
        uint32_t sessionStutterCount = 0;
        
        // Identity Validation (PID Reuse Protection)
        uint64_t creationTime = 0;
		
		// Fix: Per-session CPU tracking
        uint64_t lastCpuTime = 0;
        uint64_t lastCpuTimestamp = 0;

        // Emergency Boost Cooldown
        uint64_t lastEmergencyBoostTime = 0;

        // RAII optimization guards (Alive as long as session exists)
        std::shared_ptr<PowerSchemeGuard> powerGuard;
        std::shared_ptr<VisualsSuspend> visualGuard;
        std::shared_ptr<CacheLimiter> cacheGuard;
        std::shared_ptr<ServiceSuspensionGuard> serviceGuard;
        std::shared_ptr<InputModeGuard> inputGuard;
        std::shared_ptr<AudioModeGuard> audioGuard;
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
    std::atomic<bool> m_emergencySignal{false}; // [FIX] Thread-safe signal flag
    std::unordered_map<DWORD, GameSession> m_sessions;
    
    // PerformanceGuardian now owns the Static Profiles (Memory)
    std::unordered_map<std::wstring, GameProfile> m_profiles;
    void LoadProfiles();
    void SaveProfiles();
    GameProfile GetProfile(const std::wstring& exeName);

    // Core Logic
    void AnalyzeStutter(GameSession& session, DWORD pid);
    void ApplyProfile(DWORD pid, const GameProfile& profile);
    
    // Internal Stats Helper
    std::vector<double> CalculateStats(const std::deque<FrameData>& history);

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
    
    // [FIX] Traffic Enforcer Signal
    bool ConsumeEmergencySignal(); 

    // Is gaming boost active?
    bool HasActiveSessions();

private:
    // Background Service Management
    void SuspendBackgroundServices();
    void ResumeBackgroundServices();
};

#endif // PMAN_PERFORMANCE_H
