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

#include "session_cache.h"
#include "globals.h"
#include "utils.h"
#include "sysinfo.h"
#include <filesystem>
#include <evntprov.h> // ETW Provider Support

// [ETW] PMan Cache Provider {B8D6F7A9-3C1B-4261-9199-2475118746C5}
static const GUID PManCacheGuid = { 0xb8d6f7a9, 0x3c1b, 0x4261, { 0x91, 0x99, 0x24, 0x75, 0x11, 0x87, 0x46, 0xc5 } };
static REGHANDLE g_hCacheProvider = 0;

SessionSmartCache::SessionSmartCache(DWORD pid) {
    Log("[CACHE] Initializing SessionSmartCache for PID: " + std::to_string(pid));
    
    // [ETW] Register Provider & Emit Creation Event
    if (!g_hCacheProvider) EventRegister(&PManCacheGuid, nullptr, nullptr, &g_hCacheProvider);
    if (g_hCacheProvider) EventWriteString(g_hCacheProvider, 0, 0, L"Cache Creation Start");

    // Initialize temporary container to allow safe destruction if Init fails
    m_processData = std::make_unique<CachedProcessData>(pid, 0, L"", L"");
    
    InitializeSnapshot();
    
    if (m_isValid) {
        EnforceMemoryLimits();
    }
}

SessionSmartCache::~SessionSmartCache() {
    // Summary Statistics on Destruction
    if (g_hCacheProvider) {
        std::wstring etwMsg = L"Cache Destroyed. Hits: " + std::to_wstring(m_hits) + L" Misses: " + std::to_wstring(m_misses);
        EventWriteString(g_hCacheProvider, 0, 0, etwMsg.c_str());
    }

    if (m_isValid) {
        Log("[CACHE] Destroying SessionSmartCache. Stats - Hits: " + 
            std::to_string(m_hits.load()) + ", Misses: " + std::to_string(m_misses.load()));
    } else {
        Log("[CACHE] Destroying INVALID SessionSmartCache.");
    }
}

std::wstring SessionSmartCache::GetCanonicalProcessPath(HANDLE hProc) {
    if (!hProc) return L"";

    wchar_t path[MAX_PATH];
    // PREFERRED: GetFinalPathNameByHandleW with VOLUME_NAME_DOS
    DWORD len = GetFinalPathNameByHandleW(hProc, path, MAX_PATH, VOLUME_NAME_DOS);
    
    if (len == 0 || len >= MAX_PATH) {
        // Fallback: QueryFullProcessImageNameW
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
            return std::wstring(path);
        }
        return L"";
    }

    return std::wstring(path);
}

void SessionSmartCache::InitializeSnapshot() {
    m_isValid = false; // Default to invalid until proven success

    // 1. Topology Snapshot
    std::vector<ULONG> pCores, eCores;
    {
        std::lock_guard<std::mutex> lock(g_cpuSetMtx);
        pCores = g_pCoreSets;
        eCores = g_eCoreSets;
    }
    
    DWORD totalLogical = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (totalLogical == 0) totalLogical = g_logicalCoreCount; 

    DWORD numaNodes = 1;
    ULONG highestNodeNumber = 0;
    if (GetNumaHighestNodeNumber(&highestNodeNumber)) {
        numaNodes = highestNodeNumber + 1;
    }

    m_topology = std::make_unique<CachedTopology>(
        totalLogical,
        g_physicalCoreCount,
        numaNodes,
        g_caps.hasHybridCores,
        (totalLogical > g_physicalCoreCount),
        pCores,
        eCores
    );

    // 2. OS Flags
    m_osFlags = std::make_unique<CachedOsFlags>(
        g_caps.supportsPowerThrottling,
        g_caps.isWindows10OrNewer 
    );

    // 3. Process Identity (Critical Fail-Safe Point)
    DWORD pid = m_processData->pid;
    uint64_t createTime = 0;
    std::wstring canonicalPath = L"";
    std::wstring name = L"";

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        Log("[CACHE] ERROR: Failed to open process. PID: " + std::to_string(pid));
        return; // m_isValid remains false
    }

    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        Log("[CACHE] ERROR: Failed to get process times.");
        CloseHandle(hProc);
        return; // m_isValid remains false
    }
    createTime = FileTimeToULL(ftCreate);

    canonicalPath = GetCanonicalProcessPath(hProc);
    if (canonicalPath.empty()) {
        // requires normalized identifier. If we can't get it, cache is unsafe.
        Log("[CACHE] ERROR: Failed to resolve canonical path.");
        CloseHandle(hProc);
        return; // m_isValid remains false
    }
    
    asciiLower(canonicalPath);
    name = ExeFromPath(canonicalPath.c_str());
    CloseHandle(hProc);

    // Commit Process Data
    m_processData = std::make_unique<CachedProcessData>(pid, createTime, canonicalPath, name);
    
    // If we reached here, initialization is successful
    m_isValid = true;

    Log("[CACHE] Snapshot Validated. ID: " + WideToUtf8(name.c_str()) + 
        " PathHash: " + std::to_string(std::hash<std::wstring>{}(canonicalPath)));
}

size_t SessionSmartCache::CalculateMemoryUsage() const {
    size_t size = sizeof(*this);
    if (m_topology) size += m_topology->GetSize();
    if (m_osFlags) size += sizeof(CachedOsFlags);
    if (m_processData) size += m_processData->GetSize();
    return size;
}

void SessionSmartCache::EnforceMemoryLimits() {
    // Strict Bounding
    // Limit = 8 KB base + (1 KB * cores) + (128 bytes * count [1])
    size_t limit = 8192 + (1024 * m_topology->logicalCores) + (128 * 1);
    size_t actual = CalculateMemoryUsage();

    if (actual > limit) {
        Log("[CACHE] VIOLATION: Cache size (" + std::to_string(actual) + 
            " bytes) exceeds limit (" + std::to_string(limit) + " bytes). Disabling.");
        m_isValid = false; // Disable on policy violation
        if (g_hCacheProvider) EventWriteString(g_hCacheProvider, 0, 0, L"Cache Disabled: Memory Limit Violation");
    }
}

bool SessionSmartCache::ValidateIdentity(DWORD livePid) const {
    // Fail immediately if cache is invalid
    if (!m_isValid) return false;

    if (livePid != m_processData->pid) {
        RecordMiss();
        return false;
    }
    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, livePid);
    if (!hProc) {
        RecordMiss();
        return false; 
    }

    bool match = false;
    
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        uint64_t liveCreateTime = FileTimeToULL(ftCreate);
        
        // Primary Anti-Reuse Check
        if (liveCreateTime == m_processData->creationTime) {
            match = true;
            RecordHit();
        } else {
            Log("[CACHE] Identity Mismatch: PID reused.");
            RecordMiss();
        }
    } else {
        RecordMiss();
    }
    
    CloseHandle(hProc);
    return match;
}