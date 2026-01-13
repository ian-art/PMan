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

#include "network_monitor.h"
#include "throttle_manager.h"
#include "logger.h"
#include "utils.h"
#include "globals.h" // For g_activeNetPids
#include <winsock2.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <icmpapi.h>
#include <vector>
#include <netlistmgr.h>
#include <objbase.h> // Required for CoCreateInstance

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

NetworkMonitor g_networkMonitor;

NetworkMonitor::~NetworkMonitor() {
    Stop();
}

void NetworkMonitor::Initialize() {
    g_throttleManager.Initialize(); // Init Job Object
    if (m_running.exchange(true)) return;
    m_thread = std::thread(&NetworkMonitor::WorkerThread, this);
    Log("[NET] Network Intelligence Monitor started");
}

void NetworkMonitor::Stop() {
    if (!m_running.exchange(false)) return;
    
    {
        std::lock_guard lock(m_mtx);
        m_cv.notify_all();
    }
    
    if (m_thread.joinable()) m_thread.join();
    Log("[NET] Network Monitor stopped");
}

// Lightweight probe: Pings Cloudflare (1.1.1.1) and Google (8.8.8.8)
// Returns TRUE if connection is STABLE (<150ms, no loss)
bool NetworkMonitor::PerformLatencyProbe() {
    // Cache result for 30s to reduce ICMP spam
    static uint64_t lastCheck = 0;
    static bool lastResult = false;
    uint64_t now = GetTickCount64();
    if (now - lastCheck < 30000) return lastResult;

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;

    char sendData[] = "PManProbe";
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData);
    std::vector<char> replyBuffer(replySize);
    
    // Targets: 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google)
    unsigned long targets[] = { 0x01010101, 0x08080808 }; 
    int successCount = 0;
    DWORD totalTime = 0;

    for (unsigned long ip : targets) {
        PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer.data();
        
        // Hard timeout: 150ms
        DWORD status = IcmpSendEcho(hIcmp, ip, sendData, sizeof(sendData), 
                                  nullptr, replyBuffer.data(), replySize, 150);

        if (status > 0 && reply->Status == IP_SUCCESS) {
            successCount++;
            totalTime += reply->RoundTripTime;
        }
    }

    IcmpCloseHandle(hIcmp);

    // Criteria: At least one succeeded AND average latency <= 150ms
    if (successCount == 0) return false; // Both failed/timeout -> Unstable
    
    DWORD avgLatency = totalTime / successCount;
    lastResult = (avgLatency <= 150);
    lastCheck = now;
    return lastResult;
}

bool NetworkMonitor::ExecuteNetCommand(const wchar_t* cmd) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Run completely silent
    PROCESS_INFORMATION pi = {};
    
    // Create a mutable copy of the command string
    std::wstring cmdStr = cmd;
    
    if (CreateProcessW(nullptr, cmdStr.data(), nullptr, nullptr, FALSE, 
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000); // 10s timeout
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    return false;
}

void NetworkMonitor::AttemptAutoRepair() {
    uint64_t now = GetTickCount64();
    
    // Safety Cooldown: Wait 5 minutes between full repair cycles
    if (now - m_lastRepairTime < 300000) return;

    m_repairStage++;
    Log("[NET_REPAIR] Connection dead > 5s. Attempting Auto-Repair Stage " + std::to_string(m_repairStage));

    switch (m_repairStage) {
        case 1: // Soft Fix: DNS Flush
            Log("[NET_REPAIR] Flushing DNS Cache...");
            ExecuteNetCommand(L"cmd.exe /c ipconfig /flushdns");
            break;

        case 2: // Medium Fix: Release/Renew IP
            Log("[NET_REPAIR] Renewing IP Address...");
            ExecuteNetCommand(L"cmd.exe /c ipconfig /release && ipconfig /renew");
            break;

        case 3: // Hard Fix: Reset Adapter (Requires Admin)
            if (g_caps.hasAdminRights) {
                Log("[NET_REPAIR] Resetting Network Adapter (Winsock Reset)...");
                ExecuteNetCommand(L"cmd.exe /c netsh winsock reset && netsh int ip reset");
            } else {
                Log("[NET_REPAIR] Skipping Stage 3 (Requires Admin Rights)");
            }
            // End of cycle, start cooldown
            m_lastRepairTime = now;
            m_repairStage = 0; 
            break;
            
        default:
            m_repairStage = 0;
            m_lastRepairTime = now;
            break;
    }
}

// Scan for bandwidth-hogging processes
// Uses GetExtendedTcpTable (AV-Safe, Read-Only) to find PIDs with active connections.
void NetworkMonitor::UpdateNetworkActivityMap() {
    DWORD size = 0;
    // Query size first
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<BYTE> tableBuffer(size);
    PMIB_TCPTABLE_OWNER_PID pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());

    if (GetExtendedTcpTable(pTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        std::unordered_set<DWORD> activePids;
        std::unordered_map<DWORD, int> synSentCounts; // Track pending connections
        
        activePids.reserve(pTable->dwNumEntries);

        for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
            DWORD state = pTable->table[i].dwState;
            DWORD pid = pTable->table[i].dwOwningPid;

            // Filter for ESTABLISHED connections only (ignoring LISTENING ports)
            // This ensures we only target processes actually transferring data.
            if (state == MIB_TCP_STATE_ESTAB) {
                activePids.insert(pid);
            }
            // Detect Retry Storms (High SYN_SENT count)
            else if (state == MIB_TCP_STATE_SYN_SENT) {
                synSentCounts[pid]++;
            }
        }
        
        // Analyze Storms if Network is Unstable
        if (g_networkState.load() == NetworkState::Unstable) {
            for (const auto& [pid, count] : synSentCounts) {
                // Threshold: >5 pending connections implies a retry storm
                if (count > 5) {
                    g_throttleManager.TriggerCooldown(pid);
                }
            }
        }

        // Update Global Cache
        std::unique_lock lock(g_netActivityMtx);
        g_activeNetPids = std::move(activePids);
    }
}

NetworkState NetworkMonitor::CheckConnectivity() {
    // 1. OS-Level Check (Instant)
    INetworkListManager* pNLM = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_NetworkListManager, nullptr, 
                                CLSCTX_ALL, IID_INetworkListManager, (void**)&pNLM);
    
    if (SUCCEEDED(hr) && pNLM) {
        NLM_CONNECTIVITY connectivity;
        if (SUCCEEDED(pNLM->GetConnectivity(&connectivity))) {
            bool hasInternet = (connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET));
            if (!hasInternet) {
                pNLM->Release();
                return NetworkState::Offline;
            }
        }
        pNLM->Release();
    }

    // 2. Stability Probe (Active)
    if (PerformLatencyProbe()) {
        return NetworkState::Stable;
    }

    return NetworkState::Unstable;
}

void NetworkMonitor::WorkerThread() {
    // Initialize COM for this thread
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    while (m_running) {
        NetworkState newState = CheckConnectivity();
        NetworkState oldState = g_networkState.load();
        uint64_t now = GetTickCount64();

        if (newState != oldState) {
            g_networkState.store(newState);
            
            std::string stateStr;
            switch(newState) {
                case NetworkState::Offline: stateStr = "OFFLINE"; break;
                case NetworkState::Unstable: stateStr = "UNSTABLE (High Latency/Jitter)"; break;
                case NetworkState::Stable: stateStr = "STABLE"; break;
            }
            Log("[NET] State changed to: " + stateStr);
            
            // Reset repair logic when connection returns
            if (newState != NetworkState::Offline) {
                m_offlineStartTime = 0;
                m_repairStage = 0;
            }
            
            // Trigger Adaptive Throttling
            g_throttleManager.OnNetworkStateChange(newState);
        }

        // Auto-Repair Logic
        if (newState == NetworkState::Offline) {
            if (m_offlineStartTime == 0) {
                m_offlineStartTime = now;
            } else if (now - m_offlineStartTime > 5000) { 
                // Offline for > 5 seconds, trigger repair
                AttemptAutoRepair();
                
                // Reset timer to allow time for the repair to work before trying next stage
                // Give it 10s grace period after a repair attempt
                m_offlineStartTime = now + 10000; 
            }
        } else {
            m_offlineStartTime = 0;
        }

        // Update Process Network Map
        UpdateNetworkActivityMap();

        // Adaptive Polling: 
        // If Unstable/Offline, check frequently (5s) to recover fast.
        // If Stable, check less frequently (30s) to save resources.
        // (For now, fixed 5s as per requirement to detect lag spikes)
        std::unique_lock lock(m_mtx);
        m_cv.wait_for(lock, std::chrono::seconds(5), [this] { return !m_running; });
    }

    CoUninitialize();
}
