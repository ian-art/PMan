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

#ifndef PMAN_SESSION_CACHE_H
#define PMAN_SESSION_CACHE_H

#include "types.h"
#include "logger.h"
#include <memory>
#include <string>
#include <vector>
#include <atomic>

struct CachedTopology {
    const DWORD logicalCores;   
    const DWORD physicalCores;
    const DWORD numaNodeCount;  
    const bool isHybrid;
    const bool hasSmt;
    const std::vector<ULONG> pCoreIndices;
    const std::vector<ULONG> eCoreIndices;
    
    CachedTopology(DWORD log, DWORD phys, DWORD numa, bool hybrid, bool smt, 
                  std::vector<ULONG> pCores, std::vector<ULONG> eCores)
        : logicalCores(log), physicalCores(phys), numaNodeCount(numa), isHybrid(hybrid), hasSmt(smt),
          pCoreIndices(std::move(pCores)), eCoreIndices(std::move(eCores)) {}

    size_t GetSize() const {
        return sizeof(*this) + 
               (pCoreIndices.capacity() * sizeof(ULONG)) + 
               (eCoreIndices.capacity() * sizeof(ULONG));
    }
};

struct CachedOsFlags {
    const bool supportsEcoQoS;
    const bool isWin11; 
    
    CachedOsFlags(bool eco, bool win11) : supportsEcoQoS(eco), isWin11(win11) {}
};

struct CachedProcessData {
    const DWORD pid;
    const uint64_t creationTime; 
    const std::wstring imagePath; 
    const std::wstring imageName; 
    
    CachedProcessData(DWORD p, uint64_t t, std::wstring path, std::wstring name)
        : pid(p), creationTime(t), imagePath(std::move(path)), imageName(std::move(name)) {}

    size_t GetSize() const {
        return sizeof(*this) + 
               (imagePath.capacity() * sizeof(wchar_t)) + 
               (imageName.capacity() * sizeof(wchar_t));
    }
};

class SessionSmartCache {
public:
    explicit SessionSmartCache(DWORD pid);
    ~SessionSmartCache();

    SessionSmartCache(const SessionSmartCache&) = delete;
    SessionSmartCache& operator=(const SessionSmartCache&) = delete;

    // Fail-Safe Accessors
    // Callers MUST check IsValid() before trusting data.
    bool IsValid() const { return m_isValid; }

    const CachedTopology* GetTopology() const { return m_isValid ? m_topology.get() : nullptr; }
    const CachedOsFlags* GetOsFlags() const { return m_isValid ? m_osFlags.get() : nullptr; }
    const CachedProcessData* GetProcessData() const { return m_isValid ? m_processData.get() : nullptr; }

    // Identity Validation
    bool ValidateIdentity(DWORD livePid) const;

    // Observability
    void RecordHit() const { m_hits.fetch_add(1, std::memory_order_relaxed); }
    void RecordMiss() const { m_misses.fetch_add(1, std::memory_order_relaxed); }

private:
    void InitializeSnapshot();
    
    // Canonical Path Resolution
    static std::wstring GetCanonicalProcessPath(HANDLE hProc);

    // Memory Discipline
    size_t CalculateMemoryUsage() const;
    void EnforceMemoryLimits();

    std::unique_ptr<CachedTopology> m_topology;
    std::unique_ptr<CachedOsFlags> m_osFlags;
    std::unique_ptr<CachedProcessData> m_processData;

    bool m_isValid = false;

    // Mutable counters for const-correct telemetry
    mutable std::atomic<uint64_t> m_hits{0};
    mutable std::atomic<uint64_t> m_misses{0};
};

#endif // PMAN_SESSION_CACHE_H
