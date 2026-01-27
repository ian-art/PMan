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
#include "context.h" // Integrated Context
#include "services.h" // Needed for WindowsServiceManager type
#include "performance.h" // Performance Guardian
#include "explorer_booster.h" // Smart Explorer Booster
#include "memory_optimizer.h" // Smart RAM Cleaner
#include "input_guardian.h"   // Input Responsiveness
#include "idle_affinity.h"    // Idle Core Parking
#include "session_cache.h"    // [CACHE]
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
#define g_serviceManager (*PManContext::Get().subs.serviceMgr)
#define g_servicesSuspended (PManContext::Get().servicesSuspended)

// Performance Guardian
#define g_perfGuardian (*PManContext::Get().subs.perf)

// Explorer Booster
#define g_explorerBooster (*PManContext::Get().subs.explorer)

// Input Guardian
#define g_inputGuardian (*PManContext::Get().subs.input)

// Idle Core Parking
#define g_idleAffinityMgr (*PManContext::Get().subs.idle)

// Memory Optimizer
#define g_memoryOptimizer (*PManContext::Get().subs.mem)

// Memory Telemetry
#define g_memTelemetry (PManContext::Get().telem.mem)

// App State
#define g_running (PManContext::Get().isRunning)
#define g_reloadNow (PManContext::Get().reloadRequested)
// Fix Combine Mode (low 32) and PID (high 32) for atomic updates
extern std::atomic<uint64_t> g_policyState; 
#define g_lastMode (PManContext::Get().lastMode)
#define g_lastPid  (PManContext::Get().lastGamePid)
extern std::atomic<DWORD> g_lastRamCleanPid;

// Process Identity (PID reuse protection)
#define g_processIdentityMtx    (PManContext::Get().proc.identityMtx)
#define g_lastProcessIdentity   (PManContext::Get().proc.lastIdentity)
#define g_lockedProcessIdentity (PManContext::Get().proc.lockedIdentity)

// Process Hierarchy
#define g_hierarchyMtx      (PManContext::Get().proc.hierarchyMtx)
#define g_processHierarchy  (PManContext::Get().proc.hierarchy)
#define g_inheritedGamePids (PManContext::Get().proc.inheritedGamePids)

// Config Flags
#define g_ignoreNonInteractive (PManContext::Get().ignoreNonInteractive)
#define g_restoreOnExit        (PManContext::Get().restoreOnExit)
#define g_lockPolicy           (PManContext::Get().conf.lockPolicy)
#define g_interferenceCount    (PManContext::Get().conf.interferenceCount)
#define g_suspendUpdatesDuringGames (PManContext::Get().conf.suspendUpdatesDuringGames)
#define g_isSuspended (PManContext::Get().isSuspended)
#define g_userPaused  (PManContext::Get().isPaused)
#define g_pauseIdle            (PManContext::Get().conf.pauseIdle)
extern std::atomic<NetworkState> g_networkState;

// Idle Revert Feature
#define g_idleRevertEnabled    (PManContext::Get().conf.idleRevertEnabled)
#define g_idleTimeoutMs        (PManContext::Get().conf.idleTimeoutMs)

// Session Lock (Anti-Flapping)
extern std::atomic<bool> g_sessionLocked;
extern std::atomic<DWORD> g_lockedGamePid;
extern std::atomic<std::chrono::steady_clock::time_point::rep> g_lockStartTime;

// Prevent system sleep
extern std::atomic<bool> g_keepAwake;

// Responsiveness Recovery Config
extern std::atomic<bool> g_responsivenessRecoveryEnabled;
extern std::atomic<bool> g_recoveryPromptEnabled;

// Config Storage
#define g_setMtx           (PManContext::Get().conf.setMtx)
#define g_games            (PManContext::Get().conf.games)
#define g_browsers         (PManContext::Get().conf.browsers)
#define g_videoPlayers     (PManContext::Get().conf.videoPlayers)
#define g_gameWindows      (PManContext::Get().conf.gameWindows)
#define g_browserWindows   (PManContext::Get().conf.browserWindows)
#define g_customLaunchers  (PManContext::Get().conf.customLaunchers)
#define g_ignoredProcesses (PManContext::Get().conf.ignoredProcesses)
#define g_oldGames         (PManContext::Get().conf.oldGames)

// Event Handles & Synchronization
#define g_hIocp (PManContext::Get().runtime.hIocp)
extern HPOWERNOTIFY g_pwr1;
extern HPOWERNOTIFY g_pwr2;

#define g_shutdownMtx      (PManContext::Get().runtime.shutdownMtx)
#define g_shutdownCv       (PManContext::Get().runtime.shutdownCv)
#define g_threadCount      (PManContext::Get().runtime.threadCount)
#define g_lastConfigReload (PManContext::Get().runtime.lastConfigReload)

extern HANDLE g_hMutex; // Single instance mutex

// Hardware & OS Capabilities
#define g_caps    (PManContext::Get().sys.caps)
#define g_cpuInfo (PManContext::Get().sys.cpu)

// Fix Compatibility Flags for low-end systems
#define g_isLowCoreCount (PManContext::Get().feat.isLowCoreCount)
#define g_isLowMemory    (PManContext::Get().feat.isLowMemory)

// Hybrid Core Management
extern std::vector<ULONG> g_pCoreSets;
extern std::vector<ULONG> g_eCoreSets;
extern std::mutex g_cpuSetMtx;

// Registry & Feature States
#define g_memoryCompressionModified (PManContext::Get().feat.memoryCompressionModified)
#define g_originalMemoryCompression (PManContext::Get().feat.originalMemoryCompression)
#define g_gpuSchedulingAvailable    (PManContext::Get().feat.gpuSchedulingAvailable)
#define g_timerResolutionActive     (PManContext::Get().feat.timerResolutionActive)
#define g_originalTimerResolution   (PManContext::Get().feat.originalTimerResolution)

// CPU Topology
#define g_physicalCoreCount (PManContext::Get().sys.physicalCoreCount)
#define g_logicalCoreCount  (PManContext::Get().sys.logicalCoreCount)
#define g_physicalCoreMask  (PManContext::Get().sys.physicalCoreMask)

// Working Set Management
#define g_workingSetManagementAvailable (PManContext::Get().feat.workingSetManagementAvailable)
#define g_workingSetMtx       (PManContext::Get().proc.workingSetMtx)
#define g_originalWorkingSets (PManContext::Get().proc.originalWorkingSets)
#define g_trimTimeMtx         (PManContext::Get().proc.trimTimeMtx)
#define g_lastTrimTimes       (PManContext::Get().proc.lastTrimTimes)

// DPC/ISR Latency Management
#define g_dpcLatencyAvailable      (PManContext::Get().feat.dpcLatencyAvailable)
#define g_timerCoalescingAvailable (PManContext::Get().feat.timerCoalescingAvailable)
#define g_highResTimersActive      (PManContext::Get().feat.highResTimersActive)
#define g_dpcStateMtx            (PManContext::Get().proc.dpcStateMtx)
#define g_processesWithBoostDisabled (PManContext::Get().proc.processesWithBoostDisabled)

// Policy & Shutdown
#define g_lastPolicyChange (PManContext::Get().lastPolicyChange)
extern std::atomic<DWORD> g_cachedRegistryValue;
#define g_hShutdownEvent (PManContext::Get().runtime.hShutdownEvent)
extern DWORD g_originalRegistryValue;
#define g_etwSession       (PManContext::Get().telem.etwSession)
#define g_lastEtwHeartbeat (PManContext::Get().telem.lastEtwHeartbeat)

// Root Cause Correlation Global
#define g_lastDpcLatency (PManContext::Get().telem.lastDpcLatency)

// Network Activity Cache
// Stores PIDs that have active TCP connections (Updated by NetworkMonitor)
#define g_netActivityMtx (PManContext::Get().net.mtx)
#define g_activeNetPids  (PManContext::Get().net.activePids)

// Session Smart Cache (Atomic Raw Pointer)
#define g_sessionCache (PManContext::Get().runtime.sessionCache)

#endif // PMAN_GLOBALS_H
