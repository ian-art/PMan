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
    
    // Main loop meant to be run in a dedicated thread
    void RunThread();

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
    std::chrono::steady_clock::time_point m_lastPurgeTime;
    
    PDH_HQUERY m_pdhQuery;
    PDH_HCOUNTER m_pdhCounter;
    std::mutex m_mtx;

    // Helpers
    void EnablePrivileges();
    void InitializePageFaultCounter();
    MemorySnapshot CollectSnapshot();
    void SmartMitigate(DWORD foregroundPid);
    void FlushStandbyList();
    bool IsTargetProcess(const std::wstring& procName);
};

#endif // PMAN_MEMORY_OPTIMIZER_H