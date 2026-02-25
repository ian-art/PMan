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

#include "telemetry_agent.h"
#include "sysinfo.h"
#include "context.h"
#include "globals.h"
#include "explorer_booster.h"
#include <pdh.h>
#include <windows.h>

#pragma comment(lib, "Pdh.lib")

TelemetryAgent::~TelemetryAgent() {
    Shutdown();
}

void TelemetryAgent::Initialize() {
    if (m_running.load()) return;
    m_running.store(true);
    m_worker = std::thread(&TelemetryAgent::WorkerLoop, this);
}

void TelemetryAgent::Shutdown() {
    if (m_running.exchange(false)) {
        if (m_worker.joinable()) {
            m_worker.join();
        }
    }
}

SystemSignalSnapshot TelemetryAgent::GetLatestSnapshot() const {
    SystemSignalSnapshot snap = {};
    
    // Read from atomics (O(1))
    snap.cpuLoad = m_cachedCpuLoad.load(std::memory_order_acquire);
    snap.memoryPressure = m_cachedMemoryPressure.load(std::memory_order_acquire);
    snap.diskQueueLen = m_cachedDiskQueue.load(std::memory_order_acquire);
    snap.latencyMs = m_cachedLatency.load(std::memory_order_acquire);
    snap.isThermalThrottling = m_cachedThermal.load(std::memory_order_acquire);
    snap.userActive = m_cachedUserActive.load(std::memory_order_acquire);

    // Default values (handled by main loop or not sensed)
    snap.cpuSaturation = 0.0;
    snap.contextSwitches = 0;
    snap.requiresPerformanceBoost = false; 
    snap.isSecurityPressure = false;

    return snap;
}

void TelemetryAgent::WorkerLoop() {
    PDH_HQUERY hQuery = nullptr;
    PDH_HCOUNTER hDiskCounter = nullptr;
    PDH_HCOUNTER hThermalCounter = nullptr;
    bool pdhInitialized = false;

    // Initialize PDH on background thread
    if (PdhOpenQueryW(nullptr, 0, &hQuery) == ERROR_SUCCESS) {
        PdhAddEnglishCounterW(hQuery, L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", 0, &hDiskCounter);
        PdhAddEnglishCounterW(hQuery, L"\\Processor Information(_Total)\\% Performance Limit", 0, &hThermalCounter);
        PdhCollectQueryData(hQuery); // Prime counters
        pdhInitialized = true;
    }

    while (m_running.load()) {
        // 1. PDH Metrics (Blocking ~1-50ms)
        if (pdhInitialized) {
            PdhCollectQueryData(hQuery);
            
            PDH_FMT_COUNTERVALUE val;
            if (hDiskCounter && PdhGetFormattedCounterValue(hDiskCounter, PDH_FMT_DOUBLE, nullptr, &val) == ERROR_SUCCESS) {
                m_cachedDiskQueue.store(val.doubleValue, std::memory_order_release);
            } else {
                m_cachedDiskQueue.store(0.0, std::memory_order_release);
            }

            if (hThermalCounter && PdhGetFormattedCounterValue(hThermalCounter, PDH_FMT_DOUBLE, nullptr, &val) == ERROR_SUCCESS) {
                // If Performance Limit < 99%, system is throttling
                m_cachedThermal.store(val.doubleValue < 99.0, std::memory_order_release);
            } else {
                m_cachedThermal.store(false, std::memory_order_release);
            }
        }

        // 2. CPU Load (SysInfo)
        // Moved from main thread to background to prevent GetSystemTimes overhead
        m_cachedCpuLoad.store(GetSystemCpuLoad(), std::memory_order_release);

        // 3. Memory Pressure
        MEMORYSTATUSEX mem = { sizeof(mem) };
        if (GlobalMemoryStatusEx(&mem)) {
            m_cachedMemoryPressure.store((double)mem.dwMemoryLoad, std::memory_order_release);
        }

        // 4. Latency (Atomic read) - Converted from microseconds to milliseconds
        m_cachedLatency.store(PManContext::Get().telem.lastDpcLatency.load(std::memory_order_relaxed) / 1000.0, std::memory_order_release);

        // 5. User Activity (Global)
        // Checks if user input occurred in the last 30 seconds
        uint64_t lastInput = PManContext::Get().subs.explorer ? PManContext::Get().subs.explorer->GetLastUserActivity() : 0;
        m_cachedUserActive.store((GetTickCount64() - lastInput) < 30000, std::memory_order_release);

        // Poll Rate: 4Hz (250ms)
        // Sufficient for thermal/disk decisions without spamming PDH
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    if (hQuery) PdhCloseQuery(hQuery);
}
