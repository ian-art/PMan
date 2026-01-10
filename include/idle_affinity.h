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

#ifndef PMAN_IDLE_AFFINITY_H
#define PMAN_IDLE_AFFINITY_H

#include <windows.h>
#include <unordered_map>
#include <mutex>
#include <atomic>

class IdleAffinityManager {
public:
    void Initialize();
    void Shutdown();
    
    // Updates the idle state and applies/restores affinity
    void OnIdleStateChanged(bool isIdle);
    
    // Handles new processes starting while system is idle
    void OnProcessStart(DWORD pid);
    
    bool IsIdle() const { return m_isIdle.load(); }

    // Config
    void UpdateConfig(bool enabled, int reservedCores, uint32_t minRamGB);

private:
    std::atomic<bool> m_enabled{false};
    std::atomic<bool> m_isIdle{false};
    std::atomic<int> m_reservedCores{2};
    std::atomic<uint32_t> m_minRamGB{4};
    
    std::unordered_map<DWORD, DWORD_PTR> m_originalAffinity; // PID -> Original mask
    std::mutex m_mtx;
    
    void ApplyIdleAffinity();
    void RestoreAllAffinity();
    void SetProcessIdleAffinity(DWORD pid, DWORD_PTR targetMask);
    bool IsSafeToPark();
};

#endif // PMAN_IDLE_AFFINITY_H
