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

#include "build_options.h"
#ifndef PMAN_GLOBALS_H
#define PMAN_GLOBALS_H

#include "types.h"
#include "services.h" // Needed for WindowsServiceManager type
#include "performance.h" // Performance Guardian
#include "explorer_booster.h" // Smart Explorer Booster
#include "memory_optimizer.h" // Smart RAM Cleaner
#include "input_guardian.h"   // Input Responsiveness
#include <atomic>
#include <mutex>
#include <shared_mutex>

// Network Intelligence
enum class NetworkState {
    Offline = 0,    // No internet access
    Unstable = 1,   // High latency (>150ms) or packet loss
    Stable = 2      // Low latency, reliable connection
};

#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <condition_variable>
#include <chrono>

// Service Manager
extern WindowsServiceManager g_serviceManager;
extern std::atomic<bool> g_servicesSuspended;

// Performance Guardian
extern PerformanceGuardian g_perfGuardian;

// Explorer Booster
extern ExplorerBooster g_explorerBooster;

// Input Guardian
extern InputGuardian g_inputGuardian;

// Memory Optimizer
extern MemoryOptimizer g_memoryOptimizer;

// Memory Telemetry
extern MemoryTelemetry g_memTelemetry;

// App State
extern std::atomic<bool> g_running;
extern std::atomic<bool> g_reloadNow;
// Fix Combine Mode (low 32) and PID (high 32) for atomic updates
extern std::atomic<uint64_t> g_policyState; 
extern std::atomic<int>   g_lastMode; // Kept for legacy reads, updated after
extern std::atomic<DWORD> g_lastPid;  // Kept for legacy reads, updated after
extern std::atomic<DWORD> g_lastRamCleanPid;

// Process Identity (PID reuse protection)
extern std::mutex g_processIdentityMtx;
extern ProcessIdentity g_lastProcessIdentity;
extern ProcessIdentity g_lockedProcessIdentity;

// Process Hierarchy
extern std::shared_mutex g_hierarchyMtx;
extern std::unordered_map<ProcessIdentity, ProcessNode, ProcessIdentityHash> g_processHierarchy GUARDED_BY(g_hierarchyMtx);
extern std::unordered_map<DWORD, ProcessIdentity> g_inheritedGamePids GUARDED_BY(g_hierarchyMtx);

// Config Flags
extern std::atomic<bool> g_ignoreNonInteractive;
extern std::atomic<bool> g_restoreOnExit;
extern std::atomic<bool> g_lockPolicy; 
extern std::atomic<int>  g_interferenceCount;
extern std::atomic<bool> g_suspendUpdatesDuringGames;
extern std::atomic<bool> g_isSuspended;
extern std::atomic<bool> g_userPaused;
extern std::atomic<NetworkState> g_networkState;

// Idle Revert Feature
extern std::atomic<bool> g_idleRevertEnabled;
extern std::atomic<uint32_t> g_idleTimeoutMs; // Store in MS for precision

// Session Lock (Anti-Flapping)
extern std::atomic<bool> g_sessionLocked;
extern std::atomic<DWORD> g_lockedGamePid;
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lockStartTime;

// Config Storage
extern std::shared_mutex g_setMtx;
extern std::unordered_set<std::wstring> g_games GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_browsers GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_videoPlayers GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_gameWindows GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_browserWindows GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_customLaunchers GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_ignoredProcesses GUARDED_BY(g_setMtx);
extern std::unordered_set<std::wstring> g_oldGames GUARDED_BY(g_setMtx); // Legacy/DX9 Games

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

// Fix Compatibility Flags for low-end systems
extern std::atomic<bool> g_isLowCoreCount;
extern std::atomic<bool> g_isLowMemory;

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
extern std::unordered_map<DWORD, SIZE_T> g_originalWorkingSets GUARDED_BY(g_workingSetMtx);
extern std::mutex g_trimTimeMtx;
extern std::unordered_map<DWORD, std::chrono::steady_clock::time_point> g_lastTrimTimes GUARDED_BY(g_trimTimeMtx);

// DPC/ISR Latency Management
extern std::atomic<bool> g_dpcLatencyAvailable;
extern std::atomic<bool> g_timerCoalescingAvailable;
extern std::atomic<bool> g_highResTimersActive;
extern std::mutex g_dpcStateMtx;
extern std::unordered_map<DWORD, bool> g_processesWithBoostDisabled GUARDED_BY(g_dpcStateMtx);

// Policy & Shutdown
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lastPolicyChange;
extern std::atomic<DWORD> g_cachedRegistryValue;
extern HANDLE g_hShutdownEvent;
extern DWORD g_originalRegistryValue;
extern std::atomic<TRACEHANDLE> g_etwSession;
extern std::atomic<uint64_t> g_lastEtwHeartbeat; // ETW Liveness

// Root Cause Correlation Global
extern std::atomic<double> g_lastDpcLatency;

// Network Activity Cache
// Stores PIDs that have active TCP connections (Updated by NetworkMonitor)
extern std::shared_mutex g_netActivityMtx;
extern std::unordered_set<DWORD> g_activeNetPids GUARDED_BY(g_netActivityMtx);

#endif // PMAN_GLOBALS_H
