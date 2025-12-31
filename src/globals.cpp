#include "globals.h"

// Service Manager
WindowsServiceManager g_serviceManager;
std::atomic<bool> g_servicesSuspended{false};

// Performance Guardian
PerformanceGuardian g_perfGuardian;

// Explorer Booster
ExplorerBooster g_explorerBooster;

// Memory Telemetry
MemoryTelemetry g_memTelemetry{};

// App State
std::atomic<bool> g_running{true};
std::atomic<bool> g_reloadNow{false};
std::atomic<uint64_t> g_policyState{0}; // Fix
std::atomic<DWORD> g_lastPid{0};
std::atomic<int>   g_lastMode{0}; 
std::atomic<DWORD> g_lastRamCleanPid{0};

// Process Identity
std::mutex g_processIdentityMtx;
ProcessIdentity g_lastProcessIdentity = {0, {0, 0}};
ProcessIdentity g_lockedProcessIdentity = {0, {0, 0}};

// Process Hierarchy
std::shared_mutex g_hierarchyMtx;
std::unordered_map<ProcessIdentity, ProcessNode, ProcessIdentityHash> g_processHierarchy;
std::unordered_map<DWORD, ProcessIdentity> g_inheritedGamePids;

// Config Flags
std::atomic<bool> g_ignoreNonInteractive{true};
std::atomic<bool> g_restoreOnExit{true};
std::atomic<bool> g_lockPolicy{false};
std::atomic<int>  g_interferenceCount{0};
std::atomic<bool> g_suspendUpdatesDuringGames{false};
std::atomic<bool> g_isSuspended{false};

// Idle Revert Feature
std::atomic<bool> g_idleRevertEnabled{true};
std::atomic<uint32_t> g_idleTimeoutMs{300000}; // Default 5m

// Session Lock
std::atomic<bool> g_sessionLocked{false};
std::atomic<DWORD> g_lockedGamePid{0};
std::atomic<std::chrono::steady_clock::time_point::rep> g_lockStartTime{0};

// Config Storage
std::shared_mutex g_setMtx;
std::unordered_set<std::wstring> g_games;
std::unordered_set<std::wstring> g_browsers;
std::unordered_set<std::wstring> g_gameWindows;
std::unordered_set<std::wstring> g_browserWindows;
std::unordered_set<std::wstring> g_customLaunchers;
std::unordered_set<std::wstring> g_ignoredProcesses;
std::unordered_set<std::wstring> g_oldGames;

// Event Handles & Synchronization
HANDLE  g_hIocp = nullptr;
HPOWERNOTIFY g_pwr1 = nullptr;
HPOWERNOTIFY g_pwr2 = nullptr;

std::mutex g_shutdownMtx;
std::condition_variable g_shutdownCv;
std::atomic<int> g_threadCount{0};
std::atomic<std::chrono::steady_clock::time_point::rep> g_lastConfigReload{0};

HANDLE g_hMutex = nullptr;

// Hardware & OS Capabilities
OSCapabilities g_caps;
CPUInfo g_cpuInfo;

// Fix Compatibility Flags
std::atomic<bool> g_isLowCoreCount{false};
std::atomic<bool> g_isLowMemory{false};

// Hybrid Core Management
std::vector<ULONG> g_pCoreSets;
std::vector<ULONG> g_eCoreSets;
std::mutex g_cpuSetMtx;

// Registry & Feature States
std::atomic<bool> g_memoryCompressionModified{false};
std::atomic<DWORD> g_originalMemoryCompression{0xFFFFFFFF};
std::atomic<bool> g_gpuSchedulingAvailable{false};
std::atomic<ULONG> g_timerResolutionActive{0};
std::atomic<ULONG> g_originalTimerResolution{0};

// CPU Topology
DWORD g_physicalCoreCount = 0;
DWORD g_logicalCoreCount = 0;
DWORD_PTR g_physicalCoreMask = 0;

// Working Set Management
std::atomic<bool> g_workingSetManagementAvailable{false};
std::mutex g_workingSetMtx;
std::unordered_map<DWORD, SIZE_T> g_originalWorkingSets;
std::mutex g_trimTimeMtx;
std::unordered_map<DWORD, std::chrono::steady_clock::time_point> g_lastTrimTimes;

// DPC/ISR Latency Management
std::atomic<bool> g_dpcLatencyAvailable{false};
std::atomic<bool> g_timerCoalescingAvailable{false};
std::atomic<bool> g_highResTimersActive{false};
std::mutex g_dpcStateMtx;
std::unordered_map<DWORD, bool> g_processesWithBoostDisabled;

// Policy & Shutdown
std::atomic<std::chrono::steady_clock::time_point::rep> g_lastPolicyChange{0};
std::atomic<DWORD> g_cachedRegistryValue{0xFFFFFFFF};
HANDLE g_hShutdownEvent = nullptr;
DWORD g_originalRegistryValue = 0xFFFFFFFF;
std::atomic<TRACEHANDLE> g_etwSession{0};
std::atomic<uint64_t> g_lastEtwHeartbeat{0};

// Root Cause Correlation Global
std::atomic<double> g_lastDpcLatency{0.0};