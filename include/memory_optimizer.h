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

#ifndef PMAN_MEMORY_OPTIMIZER_H
#define PMAN_MEMORY_OPTIMIZER_H

#include "types.h"
#include <vector>
#include <map>
#include <atomic>
#include <mutex>
#include <string>
#include <chrono>
#include <pdh.h>

class MemoryOptimizer {
public:
    MemoryOptimizer();
    ~MemoryOptimizer();

    void Initialize();
    void Shutdown();

    // [SENSOR] Pure heuristic query: enumerates background processes and returns
    // the single worst offender PID eligible for a trim action, or 0 if none qualify.
    // Does NOT modify any process state.
    DWORD ProposeTrimTarget(DWORD foregroundPid);

    // [SENSOR] Pure heuristic query: returns foregroundPid if it is a known game
    // with a working set > 200MB and eligible for hardening, or 0 otherwise.
    // Does NOT modify any process state.
    DWORD ProposeHardenTarget(DWORD foregroundPid);

    // Memory Shield - applied by SandboxExecutor via Action_MemoryHarden lease
    void HardenProcess(DWORD pid);

    // [SENSOR] Query if any process is currently shielded
    bool IsShieldActive();

private:
    struct ProcessState {
        std::chrono::steady_clock::time_point lastTrimTime;
    };

    struct MemorySnapshot {
        DWORD commitPercent;
        DWORD memoryLoadPercent;
        DWORD hardFaultsPerSec;
    };

    // Configuration
    const DWORD HARD_FAULT_THRESHOLD = 2000;      // per second
    const SIZE_T MIN_MEM_TO_TRIM = 30 * 1024 * 1024; // 30MB
    const DWORD PURGE_COOLDOWN_SEC = 300;         // 5 Minutes
    const DWORD PROCESS_COOLDOWN_SEC = 30;        // 30 Seconds per process

    // State
    std::atomic<bool> m_running;
    std::map<DWORD, ProcessState> m_processTracker;
    std::vector<DWORD> m_hardenedPids; // [TRACK] Keep track of locked games
    std::chrono::steady_clock::time_point m_lastPurgeTime;
    
    PDH_HQUERY m_pdhQuery;
    PDH_HCOUNTER m_pdhCounter;
    std::mutex m_mtx;

    // Helpers
    void EnablePrivileges();
    void InitializePageFaultCounter();
    MemorySnapshot CollectSnapshot();
    // void SmartMitigate(DWORD foregroundPid); // Moved to Public
    void FlushStandbyList();
    bool IsTargetProcess(const std::wstring& procName);
};

#endif // PMAN_MEMORY_OPTIMIZER_H
