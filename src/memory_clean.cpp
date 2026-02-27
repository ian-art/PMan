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

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <string>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== NT Definitions ====================
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0L)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS_EXT {
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemRegistryReconciliationInformation = 84,
    SystemCombinePhysicalMemoryInformation = 130
} SYSTEM_INFORMATION_CLASS_EXT;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryCaptureAccessedBits = 0,
    MemoryCaptureAndResetAccessedBits = 1,
    MemoryEmptyWorkingSets = 2,
    MemoryFlushModifiedList = 3,
    MemoryPurgeStandbyList = 4,
    MemoryPurgeLowPriorityStandbyList = 5
} SYSTEM_MEMORY_LIST_COMMAND;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION;

typedef struct _MEMORY_COMBINE_INFORMATION_EX {
    HANDLE Handle;
    ULONG PagesCombined;
} MEMORY_COMBINE_INFORMATION_EX;

typedef struct _SYSTEM_MEMORY_LIST_INFORMATION {
    ULONG_PTR ZeroPageCount;
    ULONG_PTR FreePageCount;
    ULONG_PTR ModifiedPageCount;
    ULONG_PTR ModifiedNoWritePageCount;
    ULONG_PTR BadPageCount;
    ULONG_PTR PageCountByPriority[8];
    ULONG_PTR RepurposedPageCountByPriority[8];
} SYSTEM_MEMORY_LIST_INFORMATION;

// Mount manager definitions
#define MOUNTMGR_DEVICE_NAME L"\\Device\\MountPointManager"
#define IOCTL_MOUNTMGR_QUERY_POINTS CTL_CODE(0x6D, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MOUNTMGR_MOUNT_POINT {
    ULONG SymbolicLinkNameOffset;
    USHORT SymbolicLinkNameLength;
    USHORT Reserved1;
    ULONG UniqueIdOffset;
    USHORT UniqueIdLength;
    USHORT Reserved2;
    ULONG DeviceNameOffset;
    USHORT DeviceNameLength;
    USHORT Reserved3;
} MOUNTMGR_MOUNT_POINT, *PMOUNTMGR_MOUNT_POINT;

typedef struct _MOUNTMGR_MOUNT_POINTS {
    ULONG Size;
    ULONG NumberOfMountPoints;
    MOUNTMGR_MOUNT_POINT MountPoints[1];
} MOUNTMGR_MOUNT_POINTS, *PMOUNTMGR_MOUNT_POINTS;

#define MOUNTMGR_IS_VOLUME_NAME(name) \
    ((name)->Length >= 96 && \
     (name)->Buffer[0] == L'\\' && \
     (name)->Buffer[1] == L'?' && \
     (name)->Buffer[2] == L'?' && \
     (name)->Buffer[3] == L'\\' && \
     (name)->Buffer[4] == L'V' && \
     (name)->Buffer[5] == L'o' && \
     (name)->Buffer[6] == L'l' && \
     (name)->Buffer[7] == L'u' && \
     (name)->Buffer[8] == L'm' && \
     (name)->Buffer[9] == L'e' && \
     (name)->Buffer[10] == L'{')

// Memory info structure
typedef struct _MEMORY_INFO {
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } physical_memory;
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } page_file;
    struct {
        ULONGLONG total_bytes;
        ULONGLONG free_bytes;
        ULONGLONG used_bytes;
        double percent_f;
        ULONG percent;
    } system_cache;
} MEMORY_INFO, *PMEMORY_INFO;

// NT functions
extern "C" {
    NTSTATUS NTAPI NtSetSystemInformation(ULONG, PVOID, ULONG);
    NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    NTSTATUS NTAPI NtFlushBuffersFile(HANDLE, PIO_STATUS_BLOCK);
    NTSTATUS NTAPI NtClose(HANDLE);
    VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
}

// ==================== Helper Functions ====================
bool IsElevated() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    
    TOKEN_ELEVATION elevation;
    DWORD size;
    bool result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) 
                  && elevation.TokenIsElevated;
    
    CloseHandle(token);
    return result;
}

bool EnablePrivileges() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    
    const wchar_t* privilegeNames[] = {
        L"SeProfileSingleProcessPrivilege",
        L"SeIncreaseQuotaPrivilege"
    };
    
    bool success = true;
    for (const wchar_t* name : privilegeNames) {
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, name, &luid)) {
            success = false;
            continue;
        }
        
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if (!AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL))
            success = false;
    }
    
    CloseHandle(token);
    return success;
}

ULONG GetPageSize() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwPageSize;
}

std::string FormatBytesize64(ULONGLONG bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit]);
    return std::string(buffer);
}

bool IsWindowsVersionOrGreater(DWORD major, DWORD minor) {
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0 };
    osvi.dwMajorVersion = major;
    osvi.dwMinorVersion = minor;
    
    DWORDLONG condMask = 0;
    condMask = VerSetConditionMask(condMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    condMask = VerSetConditionMask(condMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, condMask) != FALSE;
}

void GetMemoryInfo(PMEMORY_INFO memInfo) {
    MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
    GlobalMemoryStatusEx(&memStatus);
    
    memInfo->physical_memory.total_bytes = memStatus.ullTotalPhys;
    memInfo->physical_memory.free_bytes = memStatus.ullAvailPhys;
    memInfo->physical_memory.used_bytes = memStatus.ullTotalPhys - memStatus.ullAvailPhys;
    memInfo->physical_memory.percent_f = static_cast<double>(memStatus.dwMemoryLoad);
    memInfo->physical_memory.percent = memStatus.dwMemoryLoad;
    
    memInfo->page_file.total_bytes = memStatus.ullTotalPageFile;
    memInfo->page_file.free_bytes = memStatus.ullAvailPageFile;
    memInfo->page_file.used_bytes = memStatus.ullTotalPageFile - memStatus.ullAvailPageFile;
    memInfo->page_file.percent_f = memStatus.ullTotalPageFile ? 
        (100.0 * memInfo->page_file.used_bytes / memStatus.ullTotalPageFile) : 0.0;
    memInfo->page_file.percent = static_cast<ULONG>(memInfo->page_file.percent_f);
    
    PERFORMANCE_INFORMATION perfInfo = { sizeof(perfInfo) };
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
        memInfo->system_cache.total_bytes = perfInfo.SystemCache * perfInfo.PageSize;
        memInfo->system_cache.used_bytes = perfInfo.KernelTotal * perfInfo.PageSize;
        memInfo->system_cache.free_bytes = memInfo->system_cache.total_bytes - 
                                           memInfo->system_cache.used_bytes;
        memInfo->system_cache.percent_f = memInfo->system_cache.total_bytes ?
            (100.0 * memInfo->system_cache.used_bytes / memInfo->system_cache.total_bytes) : 0.0;
        memInfo->system_cache.percent = static_cast<ULONG>(memInfo->system_cache.percent_f);
    }
}

void PrintMemoryListStats(const char* label, const SYSTEM_MEMORY_LIST_INFORMATION& info, ULONG pageSize) {
    ULONGLONG mod = (info.ModifiedPageCount + info.ModifiedNoWritePageCount) * pageSize;
    ULONGLONG standby = 0;
    for (int i = 0; i < 8; ++i) standby += info.PageCountByPriority[i] * pageSize;

    printf("%s\n", label);
    printf("  Zero pages     : %s\n", FormatBytesize64(info.ZeroPageCount * pageSize).c_str());
    printf("  Free pages     : %s\n", FormatBytesize64(info.FreePageCount * pageSize).c_str());
    printf("  Modified pages : %s\n", FormatBytesize64(mod).c_str());
    printf("  Standby pages  : %s\n", FormatBytesize64(standby).c_str());
    printf("  Repurposed     : %s\n", FormatBytesize64(info.RepurposedPageCountByPriority[0] * pageSize).c_str());
}

bool GetMemoryListInfo(SYSTEM_MEMORY_LIST_INFORMATION& out) {
    BYTE buffer[1024] = {};
    ULONG retLen = 0;
    NTSTATUS st = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemMemoryListInformation, buffer, sizeof(buffer), &retLen);
    if (NT_SUCCESS(st) || st == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        size_t copy = (std::min)(retLen, (ULONG)sizeof(out));
        memcpy(&out, buffer, copy);
        return true;
    }
    return false;
}

NTSTATUS FlushVolumeCacheAccurate() {
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    IO_STATUS_BLOCK iosb;
    HANDLE hDevice = NULL;
    NTSTATUS status;
    
    RtlInitUnicodeString(&deviceName, MOUNTMGR_DEVICE_NAME);
    oa.Length = sizeof(oa);
    oa.ObjectName = &deviceName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    
    status = NtCreateFile(
        &hDevice,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    
    if (!NT_SUCCESS(status)) {
        printf("FAILED (0x%08X)\n", status);
        return status;
    }
    
    MOUNTMGR_MOUNT_POINT input = {0};
    BYTE buffer[16384];
    PMOUNTMGR_MOUNT_POINTS mountPoints = (PMOUNTMGR_MOUNT_POINTS)buffer;
    
    status = NtDeviceIoControlFile(
        hDevice,
        NULL,
        NULL,
        NULL,
        &iosb,
        IOCTL_MOUNTMGR_QUERY_POINTS,
        &input,
        sizeof(input),
        mountPoints,
        sizeof(buffer)
    );
    
    if (!NT_SUCCESS(status)) {
        printf("FAILED (0x%08X)\n", status);
        NtClose(hDevice);
        return status;
    }
    
    ULONG flushedCount = 0;
    for (ULONG i = 0; i < mountPoints->NumberOfMountPoints; i++) {
        PMOUNTMGR_MOUNT_POINT mp = &mountPoints->MountPoints[i];
        
        UNICODE_STRING volumeName;
        volumeName.Length = mp->SymbolicLinkNameLength;
        volumeName.MaximumLength = mp->SymbolicLinkNameLength + sizeof(WCHAR);
        volumeName.Buffer = (PWSTR)((PBYTE)mountPoints + mp->SymbolicLinkNameOffset);
        
        if (MOUNTMGR_IS_VOLUME_NAME(&volumeName)) {
            OBJECT_ATTRIBUTES volOa = { sizeof(volOa) };
            volOa.Length = sizeof(volOa);
            volOa.ObjectName = &volumeName;
            volOa.Attributes = OBJ_CASE_INSENSITIVE;
            
            HANDLE hVolume;
            IO_STATUS_BLOCK volIosb;
            
            status = NtCreateFile(
                &hVolume,
                FILE_WRITE_DATA | SYNCHRONIZE,
                &volOa,
                &volIosb,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
            );
            
            if (NT_SUCCESS(status)) {
                status = NtFlushBuffersFile(hVolume, &volIosb);
                if (NT_SUCCESS(status)) {
                    flushedCount++;
                }
                NtClose(hVolume);
            }
        }
    }
    
    NtClose(hDevice);
    printf("OK (flushed %lu volumes)\n", flushedCount);
    return STATUS_SUCCESS;
}

// ==================== Core Cleaning Engine ====================
ULONGLONG PerformClean(bool aggressive, bool dryRun) {
    printf("\n=== Memory Cleaner %s mode ===\n", aggressive ? "FULL/AGGRESSIVE" : "SAFE");
    if (dryRun) printf("*** DRY-RUN MODE - no changes will be made ***\n");

    if (!EnablePrivileges()) printf("Warning: Could not enable all privileges\n");

    ULONG pageSize = GetPageSize();
    MEMORY_INFO memBefore{}, memAfter{};
    SYSTEM_MEMORY_LIST_INFORMATION listBefore{}, listAfter{};

    GetMemoryInfo(&memBefore);
    GetMemoryListInfo(listBefore);

    PrintMemoryListStats("=== BEFORE ===", listBefore, pageSize);
    printf("Physical used : %s (%.1f%%)\n\n", FormatBytesize64(memBefore.physical_memory.used_bytes).c_str(), memBefore.physical_memory.percent_f);

    auto doOp = [&](const char* name, SYSTEM_MEMORY_LIST_COMMAND cmd, bool versionCheck = true, DWORD maj = 0, DWORD min = 0) {
        if (versionCheck && !IsWindowsVersionOrGreater(maj, min)) {
            printf("  -> %s skipped (requires newer Windows)\n", name);
            return;
        }
        printf("  -> %s... ", name);
        if (dryRun) { printf("DRY-RUN (skipped)\n"); return; }

        auto t0 = std::chrono::high_resolution_clock::now();
        NTSTATUS st = NtSetSystemInformation(SystemMemoryListInformation, &cmd, sizeof(cmd));
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
        printf(NT_SUCCESS(st) ? "OK (%lld ms)\n" : "FAILED (0x%08X, %lld ms)\n", st, ms);
    };

    auto doFileCache = [&]() {
        printf("  -> Clearing system file cache... ");
        if (dryRun) { printf("DRY-RUN\n"); return; }
        auto t0 = std::chrono::high_resolution_clock::now();
        SYSTEM_FILECACHE_INFORMATION sfci = {0};
        sfci.MinimumWorkingSet = sfci.MaximumWorkingSet = SIZE_MAX;
        NTSTATUS st = NtSetSystemInformation(SystemFileCacheInformationEx, &sfci, sizeof(sfci));
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
        printf(NT_SUCCESS(st) ? "OK (%lld ms)\n" : "FAILED (0x%08X)\n", st, ms);
    };

    // Safe operations (always)
    doOp("Emptying working sets", MemoryEmptyWorkingSets);
    doOp("Purging low-priority standby", MemoryPurgeLowPriorityStandbyList);

    // Registry cache (Win8.1+)
    if (IsWindowsVersionOrGreater(6, 3)) {
        printf("  -> Flushing registry cache... ");
        if (!dryRun) {
            auto t0 = std::chrono::high_resolution_clock::now();
            NTSTATUS st = NtSetSystemInformation(SystemRegistryReconciliationInformation, NULL, 0);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            printf(NT_SUCCESS(st) ? "OK (%lld ms)\n" : "FAILED (0x%08X)\n", st, ms);
        } else printf("DRY-RUN\n");
    }

    // Memory combine (Win10+)
    if (IsWindowsVersionOrGreater(10, 0)) {
        printf("  -> Combining memory lists... ");
        if (!dryRun) {
            auto t0 = std::chrono::high_resolution_clock::now();
            MEMORY_COMBINE_INFORMATION_EX combineInfo = {0};
            NTSTATUS st = NtSetSystemInformation(SystemCombinePhysicalMemoryInformation, &combineInfo, sizeof(combineInfo));
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - t0).count();
            printf(NT_SUCCESS(st) ? "OK (%lld ms)\n" : "FAILED (0x%08X)\n", st, ms);
        } else printf("DRY-RUN\n");
    }

    // Aggressive-only
    if (aggressive) {
        printf("\n--- Aggressive operations ---\n");
        doOp("Flushing modified page list", MemoryFlushModifiedList);
        doOp("Purging FULL standby list", MemoryPurgeStandbyList);
        doFileCache();
        printf("  -> Flushing volume caches... ");
        if (!dryRun) FlushVolumeCacheAccurate();
        else printf("DRY-RUN\n");
    }

    GetMemoryInfo(&memAfter);
    GetMemoryListInfo(listAfter);

    ULONGLONG freedPhys = memBefore.physical_memory.used_bytes > memAfter.physical_memory.used_bytes ?
                          memBefore.physical_memory.used_bytes - memAfter.physical_memory.used_bytes : 0;

    printf("\n=== AFTER ===\n");
    PrintMemoryListStats("Memory list", listAfter, pageSize);
    printf("Physical used : %s (%.1f%%)\n", FormatBytesize64(memAfter.physical_memory.used_bytes).c_str(), memAfter.physical_memory.percent_f);
    printf("\n========================================\n");
    printf("TOTAL FREED     : %s\n", FormatBytesize64(freedPhys).c_str());
    printf("========================================\n");
    
    return freedPhys;
}
