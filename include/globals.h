#ifndef PMAN_GLOBALS_H
#define PMAN_GLOBALS_H

#include "types.h"
#include "services.h" // Needed for WindowsServiceManager type
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <condition_variable>
#include <chrono>

// Service Manager
extern WindowsServiceManager g_serviceManager;
extern std::atomic<bool> g_servicesSuspended;

// Memory Telemetry
extern MemoryTelemetry g_memTelemetry;

// App State
extern std::atomic<bool> g_running;
extern std::atomic<bool> g_reloadNow;
extern std::atomic<DWORD> g_lastPid;
extern std::atomic<int>   g_lastMode; // 0 unknown, 1 game, 2 browser
extern std::atomic<DWORD> g_lastRamCleanPid;

// Process Identity (PID reuse protection)
extern std::mutex g_processIdentityMtx;
extern ProcessIdentity g_lastProcessIdentity;
extern ProcessIdentity g_lockedProcessIdentity;

// Config Flags
extern std::atomic<bool> g_ignoreNonInteractive;
extern std::atomic<bool> g_restoreOnExit;
extern std::atomic<bool> g_lockPolicy; 
extern std::atomic<int>  g_interferenceCount;
extern std::atomic<bool> g_suspendUpdatesDuringGames;

// Session Lock (Anti-Flapping)
extern std::atomic<bool> g_sessionLocked;
extern std::atomic<DWORD> g_lockedGamePid;
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lockStartTime;

// Config Storage
extern std::shared_mutex g_setMtx;
extern std::unordered_set<std::string> g_games;
extern std::unordered_set<std::string> g_browsers;
extern std::unordered_set<std::string> g_gameWindows;
extern std::unordered_set<std::string> g_browserWindows;

// Event Handles & Synchronization
extern HANDLE  g_hIocp;
extern HPOWERNOTIFY g_pwr1;
extern HPOWERNOTIFY g_pwr2;

extern std::mutex g_shutdownMtx;
extern std::condition_variable g_shutdownCv;
extern std::atomic<int> g_threadCount;
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lastConfigReload;

extern HANDLE g_hMutex; // Single instance mutex

// Hardware & OS Capabilities
extern OSCapabilities g_caps;
extern CPUInfo g_cpuInfo;

// Hybrid Core Management
extern std::vector<ULONG> g_pCoreSets;
extern std::vector<ULONG> g_eCoreSets;
extern std::mutex g_cpuSetMtx;

// Registry & Feature States
extern std::atomic<bool> g_memoryCompressionModified;
extern std::atomic<DWORD> g_originalMemoryCompression;
extern std::atomic<bool> g_gpuSchedulingAvailable;
extern std::atomic<ULONG> g_timerResolutionActive;
extern std::atomic<ULONG> g_originalTimerResolution;

// CPU Topology
extern DWORD g_physicalCoreCount;
extern DWORD g_logicalCoreCount;
extern DWORD_PTR g_physicalCoreMask;

// Working Set Management
extern std::atomic<bool> g_workingSetManagementAvailable;
extern std::mutex g_workingSetMtx;
extern std::unordered_map<DWORD, SIZE_T> g_originalWorkingSets;
extern std::mutex g_trimTimeMtx;
extern std::unordered_map<DWORD, std::chrono::steady_clock::time_point> g_lastTrimTimes;

// DPC/ISR Latency Management
extern std::atomic<bool> g_dpcLatencyAvailable;
extern std::atomic<bool> g_timerCoalescingAvailable;
extern std::atomic<bool> g_highResTimersActive;
extern std::mutex g_dpcStateMtx;
extern std::unordered_map<DWORD, bool> g_processesWithBoostDisabled;

// Policy & Shutdown
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lastPolicyChange;
extern std::atomic<DWORD> g_cachedRegistryValue;
extern HANDLE g_hShutdownEvent;
extern DWORD g_originalRegistryValue;
extern std::atomic<TRACEHANDLE> g_etwSession;

#endif // PMAN_GLOBALS_H