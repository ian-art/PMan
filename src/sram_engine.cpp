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

#include "sram_engine.h"
#include "logger.h"
#include <pdh.h>
#include <dwmapi.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "dwmapi.lib")

#define SRAM_WINDOW_CLASS L"PMan_SRAM_Hidden"
#define WM_SRAM_PING (WM_USER + 1)
#define SENSOR_POLL_RATE_MS 250

// Config
#define HYSTERESIS_COOLDOWN_MS 2000
#define HYSTERESIS_SPIKE_COUNT 3

SramEngine& SramEngine::Get() {
    static SramEngine instance;
    return instance;
}

// Constructor: Initialize the atomic on the heap
SramEngine::SramEngine() {
    m_status = std::make_unique<std::atomic<LagStatus>>(LagStatus{0.0f, LagState::SNAPPY, 0});
}

void SramEngine::Initialize() {
    if (m_running.exchange(true)) return; // Already running

    m_thread = std::thread(&SramEngine::WorkerThread, this);
    Log("[SRAM] Core infrastructure initialized.");
}

void SramEngine::Shutdown() {
    if (!m_running.exchange(false)) return;

    DWORD tid = m_threadId.load();
    if (tid != 0) {
        // Post Quit to break the GetMessage loop
        PostThreadMessageW(tid, WM_QUIT, 0, 0);
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }
    Log("[SRAM] Stopped.");
}

LagStatus SramEngine::GetStatus() const {
    // Lock-free atomic load (via pointer)
    return m_status->load(std::memory_order_acquire);
}

DWORD SramEngine::GetThreadId() const {
    return m_threadId.load();
}

SramEngine::~SramEngine() {
    Shutdown();
}

LRESULT CALLBACK SramEngine::SramWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto& engine = SramEngine::Get();

    switch (msg) {
    case WM_SRAM_PING: {
        // 2.1 UI Latency Sensor (Receiver)
        uint64_t now = GetTickCount64();
        uint64_t sent = (uint64_t)wParam; // We sent timestamp as wParam
        if (now >= sent) {
            engine.m_uiLatencyMs = (uint32_t)(now - sent);
        }
        return 0;
    }
    case WM_INPUT: {
        // 2.3 Input Latency Sensor
        engine.CollectInputStats(lParam);
        break; // Allow DefWindowProc to cleanup
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void SramEngine::InitSensors() {
    // 2.4 System Pressure (PDH)
    if (PdhOpenQueryW(nullptr, 0, (PDH_HQUERY*)&m_hPdhQuery) == ERROR_SUCCESS) {
        // Monitor total processor queue length
        PdhAddCounterW((PDH_HQUERY)m_hPdhQuery, L"\\System\\Processor Queue Length", 0, (PDH_HCOUNTER*)&m_hPdhCounter);
        PdhCollectQueryData((PDH_HQUERY)m_hPdhQuery); // Prime the counter
    }
}

void SramEngine::CollectUiLatency() {
    // 2.1 Post a ping to ourselves
    // We send the current time; when we process the message, we check the delta.
    // This measures the congestion of OUR thread's message queue.
    uint64_t now = GetTickCount64();
    m_lastPingSent = now;
    PostThreadMessageW(m_threadId.load(), WM_SRAM_PING, (WPARAM)now, 0);
}

void SramEngine::CollectDwmStats() {
    // 2.2 DWM Composition
    DWM_TIMING_INFO timing = {};
    timing.cbSize = sizeof(timing);
    if (DwmGetCompositionTimingInfo(nullptr, &timing) == S_OK) {
        // cFramesMissed - standard field for frames the app failed to submit
        m_dwmFramesMissed = (uint32_t)timing.cFramesMissed;
    }
}

void SramEngine::CollectInputStats(LPARAM lParam) {
    // 2.3 Input Latency
    UINT dwSize = 0;
    GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
    
    if (dwSize > 0) {
        // We just track the timestamp of the last activity for now
        m_lastInputEvent = GetTickCount64();
        
        // Calculate latency: The time the event happened vs now
        // Note: GetMessageTime() is usually consistent with the event retrieval time
        RAWINPUTHEADER header;
        if (GetRawInputData((HRAWINPUT)lParam, RID_HEADER, &header, &dwSize, sizeof(RAWINPUTHEADER)) == dwSize) {
            // header.dwType can be RIM_TYPEKEYBOARD or RIM_TYPEMOUSE
            // We can't easily get the true "generation" timestamp from raw input without advanced hooks,
            // but we can measure the gap between the OS dispatching it and us receiving it if using hooks.
            // For standard RawInput, we'll assume "Input Present" is the signal we care about.
        }
    }
}

void SramEngine::CollectSystemPressure() {
    // 2.4 PDH CPU Queue
    if (m_hPdhQuery && m_hPdhCounter) {
        PDH_FMT_COUNTERVALUE fmtValue;
        if (PdhCollectQueryData((PDH_HQUERY)m_hPdhQuery) == ERROR_SUCCESS) {
            if (PdhGetFormattedCounterValue((PDH_HCOUNTER)m_hPdhCounter, PDH_FMT_DOUBLE, nullptr, &fmtValue) == ERROR_SUCCESS) {
                m_cpuQueueLength = fmtValue.doubleValue;
            }
        }
    }
}

float SramEngine::NormalizeMetric(float value, float minThreshold, float maxThreshold) {
    if (value <= minThreshold) return 0.0f;
    if (value >= maxThreshold) return 1.0f;
    return (value - minThreshold) / (maxThreshold - minThreshold);
}

void SramEngine::EvaluateState() {
    // 1. Calculate Deltas
    uint32_t dwmDelta = 0;
    if (m_dwmFramesMissed >= m_lastDwmSnapshot) {
        dwmDelta = m_dwmFramesMissed - m_lastDwmSnapshot;
    }
    m_lastDwmSnapshot = m_dwmFramesMissed; // Update history

    // 2. Normalize Metrics (0.0 - 1.0)
    // Thresholds based on roadmap: <16ms (Good), >100ms (Critical)
    float n_ui    = NormalizeMetric((float)m_uiLatencyMs, 16.0f, 100.0f);
    
    // DWM: >0 drops is bad. >3 drops (in 250ms) is critical.
    float n_dwm   = NormalizeMetric((float)dwmDelta, 0.0f, 3.0f);
    
    // Input: <16ms (Good), >50ms (Bad)
    // Note: Since we only track 'last event time' vs 'now' loosely, 
    // we use a decay logic. If input was recent, we assume latency is low unless 
    // the UI thread is blocked (which n_ui covers). 
    // For now, we use a placeholder or derived metric if we can't measure precise hardware latency.
    // Let's rely on n_ui for the heavy lifting of "responsiveness" and treat input as "time since processed".
    // Effectively, if we are processing input messages, n_input is low.
    float n_input = NormalizeMetric((float)m_inputLatencyMs, 16.0f, 60.0f);

    // CPU Pressure: Queue Length relative to cores (approx).
    // Assuming 8 cores avg. Queue > 4 is pressure. Queue > 12 is critical.
    // A more robust way is to divide by std::thread::hardware_concurrency(), 
    // but raw values work for general "responsiveness" tuning.
    float n_cpu   = NormalizeMetric((float)m_cpuQueueLength, 2.0f, 16.0f);

    // 3. Composite Scoring (Weighted Formula)
    float c_ui    = n_ui * 0.30f;
    float c_dwm   = n_dwm * 0.20f;
    float c_input = n_input * 0.20f;
    float c_cpu   = n_cpu * 0.15f;
    
    float score = c_ui + c_dwm + c_input + c_cpu;

    // 4. Map to Raw State
    LagState rawState = LagState::SNAPPY;
    if (score >= 0.65f) rawState = LagState::CRITICAL_LAG;
    else if (score >= 0.35f) rawState = LagState::LAGGING;
    else if (score >= 0.15f) rawState = LagState::SLIGHT_PRESSURE;

    // 5. Hysteresis Controller (State Machine)
    uint64_t now = GetTickCount64();
    bool stateChanged = false;

    if (rawState > m_currentLogicState) {
        // UPGRADE (Worsening): Use Spike Filter
        // Requires N consecutive bad samples to accept the worse state.
        m_consecutiveSpikes++;
        if (m_consecutiveSpikes >= HYSTERESIS_SPIKE_COUNT) {
            m_currentLogicState = rawState;
            m_lastStateChangeTime = now;
            m_consecutiveSpikes = 0;
            stateChanged = true;
        }
    } else if (rawState < m_currentLogicState) {
        // DOWNGRADE (Improving): Use Cool-down Timer
        // Must stay stable for 2 seconds before relaxing.
        m_consecutiveSpikes = 0; // Reset spikes on improvement
        if (now - m_lastStateChangeTime >= HYSTERESIS_COOLDOWN_MS) {
            m_currentLogicState = rawState;
            m_lastStateChangeTime = now;
            stateChanged = true;
        }
    } else {
        // Stable
        m_consecutiveSpikes = 0;
    }

    // 6. Publish to Atomic Contract
    LagStatus status;
    status.lag_score = score;
    status.state = m_currentLogicState;
    status.timestamp = now;
    
    m_status->store(status, std::memory_order_release);

    // Diagnostic Logging
    if (stateChanged) {
        std::string stateStr = "SNAPPY";
        if (m_currentLogicState == LagState::SLIGHT_PRESSURE) stateStr = "PRESSURE";
        else if (m_currentLogicState == LagState::LAGGING) stateStr = "LAGGING";
        else if (m_currentLogicState == LagState::CRITICAL_LAG) stateStr = "CRITICAL";

        // Identify primary contributor
        std::string culprit = "None";
        float maxVal = 0.0f;

        if (c_ui > maxVal) { maxVal = c_ui; culprit = "UI Latency (" + std::to_string(m_uiLatencyMs) + "ms)"; }
        if (c_dwm > maxVal) { maxVal = c_dwm; culprit = "DWM Drops (" + std::to_string(dwmDelta) + ")"; }
        if (c_cpu > maxVal) { maxVal = c_cpu; culprit = "CPU Queue (" + std::to_string(m_cpuQueueLength) + ")"; }
        if (c_input > maxVal) { maxVal = c_input; culprit = "Input Delay"; }

        Log("[SRAM] State Transition: " + stateStr + " (Score: " + std::to_string(score) + "). Primary Factor: " + culprit);
    }
}

void SramEngine::WorkerThread() {
    m_threadId.store(GetCurrentThreadId());

    // Correct Fix: A sensor must never compete with what it is measuring.
    // Use NORMAL to ensure we don't preempt the UI thread we are trying to measure.
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = SramWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = SRAM_WINDOW_CLASS;
    
    RegisterClassExW(&wc);

    // Create message-only window (HWND_MESSAGE)
    HWND hwnd = CreateWindowExW(0, SRAM_WINDOW_CLASS, L"SRAM_Core", 
                                0, 0, 0, 0, 0, 
                                HWND_MESSAGE, nullptr, wc.hInstance, nullptr);

    if (hwnd) {
        // 2.3 Register for Raw Input (Input Latency)
        // RIDEV_INPUTSINK enables receiving input in the background
        RAWINPUTDEVICE rid[2];
        
        // Mouse
        rid[0].usUsagePage = 0x01;
        rid[0].usUsage = 0x02;
        rid[0].dwFlags = RIDEV_INPUTSINK;
        rid[0].hwndTarget = hwnd;

        // Keyboard
        rid[1].usUsagePage = 0x01;
        rid[1].usUsage = 0x06;
        rid[1].dwFlags = RIDEV_INPUTSINK;
        rid[1].hwndTarget = hwnd;

        RegisterRawInputDevices(rid, 2, sizeof(rid[0]));

        InitSensors();

        Log("[SRAM] Worker thread active (Priority: ABOVE_NORMAL). Message loop established.");
        
        MSG msg;
        uint64_t lastPoll = 0;

        while (m_running.load()) {
            // Non-blocking Peek to allow sensor polling
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    m_running.store(false);
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            if (!m_running.load()) break;

            // Sensor Polling Loop
            uint64_t now = GetTickCount64();
            if (now - lastPoll >= SENSOR_POLL_RATE_MS) {
                CollectUiLatency();
                CollectDwmStats();
                CollectSystemPressure();
                
                // Run Logic Engine
                EvaluateState();

                lastPoll = now;
            }

            // Yield to avoid 100% CPU, but stay responsive
            Sleep(5); 
        }
    } else {
        Log("[SRAM] FATAL: Failed to create message window: " + std::to_string(GetLastError()));
    }

    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(SRAM_WINDOW_CLASS, wc.hInstance);
    m_threadId.store(0);
}

// --- Architecture Bridge ---
LagState GetSystemResponsiveness() {
    // This is the ONLY place that knows SramEngine exists for this purpose.
    return SramEngine::Get().GetStatus().state;
}
