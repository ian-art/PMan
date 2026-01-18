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

#ifndef PMAN_TYPES_H
#define PMAN_TYPES_H

// Target Windows 10
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

// --------------------------------------------------------------------------
// SDK COMPATIBILITY DEFINITIONS
// --------------------------------------------------------------------------

#ifndef SystemMemoryListInformation
#define SystemMemoryListInformation static_cast<SYSTEM_INFORMATION_CLASS>(80)
#endif

// Windows 10+ Power Throttling API definitions (for older SDKs)
#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1

typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE, *PPROCESS_POWER_THROTTLING_STATE;

typedef struct _SYSTEM_CPU_SET_INFORMATION_SAFE {
    DWORD Size;
    DWORD Type;
    union {
        struct {
            DWORD Id;
            WORD Group;
            BYTE LogicalProcessorIndex;
            BYTE CoreIndex;
            BYTE LastLevelCacheIndex;
            BYTE NumaNodeIndex;
            BYTE EfficiencyClass;
            union {
                BYTE AllFlags;
                struct {
                    BYTE Parked : 1;
                    BYTE Allocated : 1;
                    BYTE AllocatedToTargetProcess : 1;
                    BYTE RealTime : 1;
                    BYTE ReservedFlags : 4;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;
            // CRITICAL FIX: This union was missing in the minimal version.
            // It ensures correct alignment (offset 16) on both x86 and x64.
            union {
                DWORD Reserved;
                BYTE SchedulingClass;
            };
            DWORD64 AllocationTag;
        } CpuSet;
    } DUMMYUNIONNAME;
} SYSTEM_CPU_SET_INFORMATION_SAFE, *PSYSTEM_CPU_SET_INFORMATION_SAFE;

// Map to standard names so sysinfo.cpp and tweaks.cpp compile without changes
using SYSTEM_CPU_SET_INFORMATION = SYSTEM_CPU_SET_INFORMATION_SAFE;
using PSYSTEM_CPU_SET_INFORMATION = PSYSTEM_CPU_SET_INFORMATION_SAFE;

#endif

// DPC/ISR Latency Management API definitions
#ifndef THREAD_PRIORITY_ERROR_RETURN
#define THREAD_PRIORITY_ERROR_RETURN (MAXLONG)
#endif

// Process DPC priority (undocumented but stable since Vista)
#ifndef ProcessDefaultHardErrorMode
#define ProcessDefaultHardErrorMode ((PROCESS_INFORMATION_CLASS)12)
#endif

// Timer coalescing control (Windows 7+)
#ifndef PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
#define PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION 0x4
#endif

// Enhanced I/O Priority support for all Windows versions
#ifndef IO_PRIORITY_HINT
typedef enum _IO_PRIORITY_HINT {
    IoPriorityVeryLow    = 0,
    IoPriorityLow        = 1, 
    IoPriorityNormal     = 2,
    IoPriorityHigh       = 3,
    IoPriorityCritical   = 4
} IO_PRIORITY_HINT, *PIO_PRIORITY_HINT;
#endif

// Fallback for older SDKs that don't define ProcessIoPriority
#ifndef ProcessIoPriority
#define ProcessIoPriority ((PROCESS_INFORMATION_CLASS)33)
#endif

// Safe definitions for Undocumented APIs
#ifndef ProcessGpuPriority
#define ProcessGpuPriority ((PROCESS_INFORMATION_CLASS)82)
#endif

#ifndef ThreadBasePriority
#define ThreadBasePriority ((THREADINFOCLASS)3)
#endif

// Windows 10+ I/O priority structure (for newer systems)
typedef struct _IO_PRIORITY_INFO {
    ULONG Size;
    ULONG Priority;
    ULONG SubPriority;
} IO_PRIORITY_INFO, *PIO_PRIORITY_INFO;

// Working Set Management API definitions
#ifndef QUOTA_LIMITS_HARDWS_MIN_ENABLE
#define QUOTA_LIMITS_HARDWS_MIN_ENABLE  0x00000001
#define QUOTA_LIMITS_HARDWS_MIN_DISABLE 0x00000002
#define QUOTA_LIMITS_HARDWS_MAX_ENABLE  0x00000004
#define QUOTA_LIMITS_HARDWS_MAX_DISABLE 0x00000008
#endif

// Define Memory Commands if not present
#ifndef SYSTEM_MEMORY_LIST_COMMAND
typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryPurgeStandbyList = 4,
    MemoryPurgeLowPriorityStandbyList = 5
} SYSTEM_MEMORY_LIST_COMMAND;
#endif

// --------------------------------------------------------------------------
// APPLICATION TYPES
// --------------------------------------------------------------------------

// DPC importance levels (higher = more CPU priority)
typedef enum _DPC_IMPORTANCE {
    DpcImportanceLow = 0,
    DpcImportanceMedium = 1,
    DpcImportanceHigh = 2
} DPC_IMPORTANCE;

// Service state tracking enum
enum class ServiceAction { None, Stopped, Paused };

// CPU Vendor Detection
enum class CPUVendor
{
    Unknown,
    Intel,
    AMD,
	ARM64,
    Other
};

struct CPUInfo
{
    CPUVendor vendor;
    std::string brandString;
    std::string vendorString;
    bool hasAVX;
    bool hasAVX2;
    bool hasAVX512;
    
    // AMD-specific
    bool hasAmd3DVCache;
    bool hasZen3Plus;
    DWORD ccdCount;          // Chiplet Die count
    DWORD coresPerCcd;       // Cores per chiplet
    std::vector<ULONG> ccd0CoreSets;  // CCD0 (with 3D V-Cache if present)
    std::vector<ULONG> ccd1CoreSets;  // CCD1+ (no 3D V-Cache)
    
    CPUInfo() : vendor(CPUVendor::Unknown), hasAVX(false), hasAVX2(false), 
                hasAVX512(false), hasAmd3DVCache(false), hasZen3Plus(false),
                ccdCount(0), coresPerCcd(0) {}
};

// Capabilities structure
struct OSCapabilities
{
    bool isWindows10OrNewer = false;
    bool hasAdminRights = false;    // Can write to HKLM
    bool canUseEtw = false;         // Can start kernel traces
    bool hasSessionApi = false;     // Can use ProcessIdToSessionId
    bool hasHybridCores = false;
    bool supportsPowerThrottling = false;
	bool isPrismEmulated = false; // Tracks if running under x64 emulation on ARM64
};

// Memory Telemetry
#pragma warning(push)
#pragma warning(disable: 4324) // structure was padded due to alignment specifier (intentional for cache line)
struct alignas(64) MemoryTelemetry
{
    std::atomic<uint64_t> lastCommitMB;
    std::atomic<uint64_t> lastStandbyMB;
    std::atomic<uint64_t> lastAvailableMB;
    std::atomic<uint64_t> lastUpdateQpc;
	
	// Fix Initialize struct to prevent garbage telemetry data
    MemoryTelemetry() 
        : lastCommitMB(0), lastStandbyMB(0), lastAvailableMB(0), lastUpdateQpc(0) {}
};
#pragma warning(pop)

// Process identity tracking (PID + creation time to prevent PID reuse issues)
struct ProcessIdentity
{
    DWORD pid;
    FILETIME creationTime;
    
    bool operator==(const ProcessIdentity& other) const
    {
        return pid == other.pid &&
               creationTime.dwLowDateTime == other.creationTime.dwLowDateTime &&
               creationTime.dwHighDateTime == other.creationTime.dwHighDateTime;
    }
    
    bool operator!=(const ProcessIdentity& other) const
    {
        return !(*this == other);
    }
};

// IOCP Job Structure
enum class JobType : DWORD { Config, Policy, PerformanceEmergency };
struct IocpJob
{ 
    JobType type; 
    DWORD pid;
    HWND hwnd;
};

// Process Hierarchy Node
struct ProcessNode {
    ProcessIdentity identity;
    ProcessIdentity parent;
    std::vector<ProcessIdentity> children;
    int inheritedMode; // 0 = none, 1 = game, 2 = browser

    ProcessNode() : inheritedMode(0) {}
};

// Hash for ProcessIdentity to use in unordered_map
struct ProcessIdentityHash {
    std::size_t operator()(const ProcessIdentity& k) const {
        return std::hash<DWORD>()(k.pid) ^ 
               (std::hash<DWORD>()(k.creationTime.dwLowDateTime) << 1) ^ 
               (std::hash<DWORD>()(k.creationTime.dwHighDateTime) << 1);
    }
};

// Process Classification
enum class ProcessNetClass {
    Unknown = 0,
    SystemCritical,  // Kernel, AV, Security (Touch NOTHING)
    UserCritical,    // Games, Video Players, Foreground Apps (Boost)
    LatencySensitive,// VoIP, Multiplayer Games (Protect)
    NetworkBound,    // Downloaders, Updates, Cloud Sync (Throttle if Unstable)
    BulkBackground   // Indexers, Telemetry (Throttle Aggressively)
};

#endif // PMAN_TYPES_H
