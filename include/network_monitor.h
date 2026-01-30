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
 
#pragma once
#include "globals.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_set>

class NetworkMonitor {
public:
    NetworkMonitor() = default;
    ~NetworkMonitor();

    void Initialize();
    void Stop();

private:
    void WorkerThread();
    NetworkState CheckConnectivity();
    bool PerformLatencyProbe(); // Returns true if Stable, false if Unstable
    void UpdateNetworkActivityMap(); // Scan active TCP connections

    // Smart Network Repair
    void AttemptAutoRepair();
    bool ExecuteNetCommand(const wchar_t* cmd);

    // FNRO: Foreground Responsiveness
public:
    void OnForegroundWindowChanged(HWND hwnd);

private:
    void ApplyBrowserBoost(DWORD pid, const std::wstring& exeName);
    void RemoveBrowserBoost();
    void ApplyQosPolicy(const std::wstring& exeName);
    void RemoveQosPolicy(const std::wstring& exeName);
	
    // State 1
    std::wstring m_lastBoostedBrowser;
    DWORD m_lastBoostedPid = 0;
    int m_lastBoostedPriority = NORMAL_PRIORITY_CLASS;
    bool m_foregroundIsBrowser = false; // Tracks intent, not action

    // Background Traffic Protection
    void DeprioritizeBackgroundApps();
    void RestoreBackgroundApps();
    
    // TCP Sanity
    void PerformTcpSanityCheck();
    
    // State 2
    std::unordered_set<DWORD> m_throttledPids;
    bool m_areBackgroundAppsThrottled = false;

    std::thread m_thread;
    std::atomic<bool> m_running{false};
    
    // Repair State Tracking
    uint64_t m_offlineStartTime{0};
    uint64_t m_lastRepairTime{0};
    int m_repairStage{0}; // 0=None, 1=FlushDNS, 2=RenewIP, 3=ResetAdapter
    std::mutex m_mtx;
    std::condition_variable m_cv;
};

extern NetworkMonitor g_networkMonitor;
