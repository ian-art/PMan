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

#ifndef PMAN_TELEMETRY_AGENT_H
#define PMAN_TELEMETRY_AGENT_H

#include <atomic>
#include <thread>
#include <mutex>
#include "types.h" // For SystemSignalSnapshot

class TelemetryAgent {
public:
    TelemetryAgent() = default;
    ~TelemetryAgent();

    void Initialize();
    void Shutdown();
    
    // O(1) Non-blocking read for the main loop
    SystemSignalSnapshot GetLatestSnapshot() const;

private:
    void WorkerLoop();

    std::atomic<bool> m_running{false};
    std::thread m_worker;
    
    // Double Buffer / Atomic Fields
    std::atomic<double> m_cachedCpuLoad{0.0};
    std::atomic<double> m_cachedMemoryPressure{0.0};
    std::atomic<double> m_cachedDiskQueue{0.0};
    std::atomic<double> m_cachedLatency{0.0};
    std::atomic<bool> m_cachedThermal{false};
    std::atomic<bool> m_cachedUserActive{false};
};

#endif // PMAN_TELEMETRY_AGENT_H
