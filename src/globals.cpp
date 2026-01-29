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

#include "globals.h"
#include "idle_affinity.h"

// Service Manager
// g_serviceManager moved to PManContext.subs
// g_servicesSuspended moved to PManContext

// Subsystems moved to PManContext.subs

// Memory Telemetry
// g_memTelemetry moved to PManContext.telem

// App State
// g_running moved to PManContext
// g_reloadNow moved to PManContext
// g_policyState moved to PManContext
// g_lastPid moved to PManContext
// g_lastMode moved to PManContext
// g_lastRamCleanPid moved to PManContext

// Process Identity & Hierarchy
// g_processIdentityMtx, g_lastProcessIdentity, g_lockedProcessIdentity moved to PManContext.proc
// g_hierarchyMtx, g_processHierarchy, g_inheritedGamePids moved to PManContext.proc

// Config Flags
// g_ignoreNonInteractive moved to PManContext
// g_restoreOnExit moved to PManContext
// g_lockPolicy, g_interferenceCount moved to PManContext.conf
// g_suspendUpdatesDuringGames moved to PManContext.conf
// g_isSuspended moved to PManContext
// g_userPaused moved to PManContext
// g_pauseIdle moved to PManContext.conf
// g_networkState moved to PManContext.net

// Responsiveness Recovery Config moved to PManContext.conf

// Idle Revert Feature
// g_idleRevertEnabled, g_idleTimeoutMs moved to PManContext.conf

// Session Lock moved to PManContext

// Prevent system sleep moved to PManContext.conf

// g_iconTheme moved to PManContext.conf

// Config Storage
// Sets and g_setMtx moved to PManContext.conf

// Event Handles & Synchronization
// g_hIocp moved to PManContext
// g_pwr1, g_pwr2 moved to PManContext.runtime

// g_shutdownMtx, g_shutdownCv, g_threadCount moved to PManContext
// g_lastConfigReload moved to PManContext

// g_hMutex moved to PManContext.runtime

// Hardware & OS Capabilities
// g_caps moved to PManContext
// g_cpuInfo moved to PManContext

// Fix Compatibility Flags
// g_isLowCoreCount, g_isLowMemory moved to PManContext.feat

// Hybrid Core Management moved to PManContext.sys

// Registry & Feature States
// g_memoryCompressionModified, g_originalMemoryCompression moved to PManContext.feat
// g_gpuSchedulingAvailable moved to PManContext.feat
// g_timerResolutionActive, g_originalTimerResolution moved to PManContext.feat

// CPU Topology
// g_physicalCoreCount moved to PManContext
// g_logicalCoreCount moved to PManContext
// g_physicalCoreMask moved to PManContext

// Working Set Management
// g_workingSetManagementAvailable moved to PManContext.feat
// g_workingSetMtx, g_originalWorkingSets moved to PManContext.proc
// g_trimTimeMtx, g_lastTrimTimes moved to PManContext.proc

// DPC/ISR Latency Management
// g_dpcLatencyAvailable, g_timerCoalescingAvailable, g_highResTimersActive moved to PManContext.feat
// g_dpcStateMtx, g_processesWithBoostDisabled moved to PManContext.proc

// Policy & Shutdown
// g_lastPolicyChange moved to PManContext
// g_cachedRegistryValue moved to PManContext.runtime
// g_hShutdownEvent moved to PManContext
// g_originalRegistryValue moved to PManContext.runtime
// g_etwSession, g_lastEtwHeartbeat moved to PManContext.telem

// Root Cause Correlation Global
// g_lastDpcLatency moved to PManContext.telem

// Network Activity Cache
// g_netActivityMtx, g_activeNetPids moved to PManContext.net

// Session Smart Cache (Atomic Raw Pointer)
// g_sessionCache moved to PManContext.runtime
