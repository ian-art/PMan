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

/*
 * SramEngine: System Responsiveness Awareness Module
 * Core Infrastructure & Concurrency
 */
 
#pragma once
#include <windows.h>
#include <atomic>
#include <thread>
#include <cstdint>
#include "responsiveness_provider.h"
#include <memory> // Required for std::unique_ptr
#include <vector>

// Aligned for 16-byte atomic operations (CMPXCHG16B) to ensure lock-free readout
struct alignas(16) LagStatus {
    float lag_score;
    LagState state;
    uint64_t timestamp;
};

class SramEngine {
public:
    static SramEngine& Get();

    void Initialize();
    void Shutdown();
    LagStatus GetStatus() const;

    // Message Pump Access
    DWORD GetThreadId() const;

private:
    SramEngine(); // Implemented in .cpp to handle unique_ptr initialization
    
    // --- Sensor Logic ---
    void InitSensors();
    void UpdateSensors();
    void CollectUiLatency();     // 2.1
    void CollectDwmStats();      // 2.2
    void CollectInputStats(LPARAM lParam); // 2.3
    void CollectSystemPressure();// 2.4

    // Sensor Data (Raw)
    uint64_t m_lastPingSent = 0;
    uint32_t m_uiLatencyMs = 0;

    uint64_t m_lastDwmCheck = 0;
    uint32_t m_dwmFramesMissed = 0;
    
    uint64_t m_lastInputEvent = 0;
    uint32_t m_inputLatencyMs = 0;

    // PDH (CPU Queue)
    void* m_hPdhQuery = nullptr; // PdhQuery Handle
    void* m_hPdhCounter = nullptr; // Processor Queue Length
    double m_cpuQueueLength = 0.0;

    // [ADD] Kernel Latency (DPC/ISR)
    // "Ghost Latency" detector: High DPC blocks execution even if CPU Load is low.
    void CollectDpcStats();
    std::vector<uint8_t> m_prevProcInfo; // Previous snapshot for delta calc
    double m_maxDpcPercent = 0.0;     // Highest single-core DPC usage
    double m_maxIsrPercent = 0.0;     // Highest single-core ISR usage

    // --- Logic Engine ---
    void EvaluateState();
    float NormalizeMetric(float value, float minThreshold, float maxThreshold);

    // Hysteresis & History
    uint32_t m_lastDwmSnapshot = 0;      // To calculate delta frames
    uint64_t m_lastStateChangeTime = 0;  // For cool-down timer
    int m_consecutiveSpikes = 0;         // For spike filtering
    
    // Internal State Tracker (prevents atomic thrashing)
    LagState m_currentLogicState = LagState::SNAPPY;
    ~SramEngine();
    
    // Non-copyable / Isolated
    SramEngine(const SramEngine&) = delete;
    SramEngine& operator=(const SramEngine&) = delete;

    void WorkerThread();
    static LRESULT CALLBACK SramWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // Improvement: Use unique_ptr to isolate 16-byte alignment requirement
    // This prevents warning C4324 (padding) by moving the aligned storage to the heap.
    std::unique_ptr<std::atomic<LagStatus>> m_status;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::atomic<DWORD> m_threadId{ 0 };
};
