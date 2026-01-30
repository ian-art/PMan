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
#include "context.h"
#include "nt_wrapper.h"
#include "globals.h" // For g_activeNetPids
#include <winsock2.h>
#include <unordered_set>
#include <ws2tcpip.h> // [FIX] Required for iphlpapi.h SAL annotations (defines MIB_TCP6TABLE_OWNER_PID)
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
    
    // System-Level TCP Sanity Checks (Diagnostic)
    PerformTcpSanityCheck();

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

    // SAFETY REVERSION
    // Ensure no priorities or QoS tags are left stuck if we shut down
    std::lock_guard lock(m_mtx);
    if (m_lastBoostedPid != 0) {
        Log("[NET] Shutdown: Reverting browser boost for PID " + std::to_string(m_lastBoostedPid));
        RemoveBrowserBoost();
    }
    if (m_areBackgroundAppsThrottled) {
        Log("[NET] Shutdown: Restoring background apps...");
        RestoreBackgroundApps();
    }

    Log("[NET] Network Monitor stopped and state reverted");
}

void NetworkMonitor::SetBackgroundApps(std::unordered_set<std::wstring> apps) {
    std::lock_guard lock(m_appsMtx);
    m_backgroundApps = std::move(apps);
    Log("[NET] Updated background apps list: " + std::to_string(m_backgroundApps.size()) + " entries");
}

std::unordered_set<std::wstring> NetworkMonitor::GetBackgroundApps() const {
    std::lock_guard lock(m_appsMtx);
    return m_backgroundApps;
}

// Lightweight probe: Pings Cloudflare (1.1.1.1) and Google (8.8.8.8)
// Returns TRUE if connection is STABLE (<150ms, no loss)
bool NetworkMonitor::PerformLatencyProbe() {
    // Cache result for 5s (matched to WorkerThread) for fresher scoring
    static uint64_t lastCheck = 0;
    static bool lastResult = false;
    uint64_t now = GetTickCount64();
    if (now - lastCheck < 5000) return lastResult;

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;

    char sendData[] = "PManProbe";
    // [FIX] C28020: Add 8 bytes padding for IO_STATUS_BLOCK/Error info as required by IcmpSendEcho
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    std::vector<char> replyBuffer(replySize);
    
    // Targets: 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google)
    unsigned long targets[] = { 0x01010101, 0x08080808 }; 
    int successCount = 0;
    DWORD totalTime = 0;

    for (unsigned long ip : targets) {
        PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer.data();
        
        // [FIX] Increased timeout to 800ms to tolerate bufferbloat during streaming/gaming
        DWORD status = IcmpSendEcho(hIcmp, ip, sendData, sizeof(sendData), 
                                  nullptr, replyBuffer.data(), replySize, 800);

        if (status > 0 && reply->Status == IP_SUCCESS) {
            successCount++;
            totalTime += reply->RoundTripTime;
        }
    }

    IcmpCloseHandle(hIcmp);

    if (successCount > 0) {
        m_lastLatencyMs = totalTime / successCount;
        // [FIX] Relax threshold to 600ms. Streaming 4K often spikes ping to 300-500ms.
        lastResult = (m_lastLatencyMs <= 600);
    } else {
        m_lastLatencyMs = 9999; // Treat as effectively offline
        lastResult = false;
    }
    
    lastCheck = now;
    return lastResult;
}

bool NetworkMonitor::IsInteractiveApp(const std::wstring& exeName) {
    // 1. Check User Config (Browsers)
    if (g_browsers.count(exeName)) return true;

    // 2. Interactive Window Heuristic (Extended List)
    // Includes communication, gaming, and development tools that require low latency.
    static const std::unordered_set<std::wstring> EXTRA_INTERACTIVE = {
        L"discord.exe", L"steam.exe", L"code.exe", L"devenv.exe", 
        L"slack.exe", L"teams.exe", L"obs64.exe", L"spotify.exe",
        L"zoom.exe", L"parsec.exe"
    };
    return EXTRA_INTERACTIVE.count(exeName);
}

int NetworkMonitor::CalculateContentionScore() {
    int score = 0;
    
    // 1. Network Latency (Responsiveness)
    // 100ms+ is noticeable, 200ms+ is bad
    if (m_lastLatencyMs > 200) score += 50;
    else if (m_lastLatencyMs > 100) score += 30;

    // 2. CPU Load (System Pressure)
    // High CPU usage often correlates with DPC latency and scheduler contention
    double cpu = GetCpuLoad();
    if (cpu > 80.0) score += 30;
    else if (cpu > 60.0) score += 15;

    // 3. Network Congestion (Connection Count)
    // More active connections = higher probability of bufferbloat
    size_t netCount = 0;
    {
        // [FIX] Use shared_lock for std::shared_mutex (g_netActivityMtx) to allow concurrent readers
        std::shared_lock<std::shared_mutex> lock(g_netActivityMtx);
        netCount = g_activeNetPids.size();
    }
    
    // >20 active streams is typical for P2P or heavy downloading
    if (netCount > 20) score += 25;
    else if (netCount > 10) score += 10;
    
    return score;
}

void NetworkMonitor::ApplyFnroLevel(FnroLevel level) {
    if (level == m_currentFnroLevel) return;
    
    // Log state transition
    std::string levelStr;
    switch(level) {
        case FnroLevel::Off: levelStr = "OFF"; break;
        case FnroLevel::Light: levelStr = "LIGHT"; break;
        case FnroLevel::Active: levelStr = "ACTIVE"; break;
        case FnroLevel::Aggressive: levelStr = "AGGRESSIVE"; break;
    }
    Log("[FNRO] Contention Score Triggered Level: " + levelStr);

    m_currentFnroLevel = level;

    // Map levels to actions
    // Light: Bias only (Handled in ApplyBrowserBoost)
    // Active/Aggressive: Throttle background noise
    if (level >= FnroLevel::Active) {
        DeprioritizeBackgroundApps();
    } else {
        RestoreBackgroundApps();
    }
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
        UniqueHandle hProcess(pi.hProcess);
        UniqueHandle hThread(pi.hThread);
        WaitForSingleObject(hProcess.get(), 10000); // 10s timeout
        return true;
    }
    return false;
}

// =========================================================
// FNRO Implementation
// =========================================================

void NetworkMonitor::PerformTcpSanityCheck() {
    // Check for "Snake Oil" registry tweaks that break Window Auto-Tuning
    DWORD val = 0;
    bool issuesFound = false;

    // 1. Static TCP Window Size (Bad)
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"TcpWindowSize", val)) {
        Log("[NET_WARN] Static 'TcpWindowSize' detected. This disables Auto-Tuning and limits speed.");
        issuesFound = true;
    }
    
    // 2. Global Max Window Size (Bad if too small)
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"GlobalMaxTcpWindowSize", val)) {
        if (val < 65535) {
             Log("[NET_WARN] 'GlobalMaxTcpWindowSize' is extremely small (" + std::to_string(val) + "). Downloads will be slow.");
             issuesFound = true;
        }
    }

    if (!issuesFound) {
        Log("[NET] TCP System Configuration appears healthy (Auto-Tuning likely active).");
    }
}

void NetworkMonitor::OnForegroundWindowChanged(HWND hwnd) {
    if (!hwnd) return;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return;

    // 1. Identify Foreground Process
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return;

    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) return;
    
    std::wstring exeName = ExeFromPath(path);

    // 2. Check Interactive Heuristic (Reuse Context + Internal List)
    bool isInteractive = IsInteractiveApp(exeName);

    std::lock_guard lock(m_mtx);

    // 3. Logic: Apply Boost if Interactive, Revert if Focus Lost
    if (isInteractive) {
        m_foregroundIsInteractive = true;

        if (pid != m_lastBoostedPid) {
            // Level 1: Instant Priority Bias (Always Safe)
            RemoveBrowserBoost(); 
            ApplyBrowserBoost(pid, exeName);
        }
        
        // Defer Level 2 (Throttling) to the Contention Scorer in WorkerThread
    } else {
        m_foregroundIsInteractive = false;

        // Non-interactive focused: Full Stand Down
        if (m_lastBoostedPid != 0) {
            RemoveBrowserBoost();
            RestoreBackgroundApps(); // Always restore when focus is lost
        }
    }
}

void NetworkMonitor::ApplyBrowserBoost(DWORD pid, const std::wstring& exeName) {
    Log("[FNRO] Boosting Network Responsiveness for: " + WideToUtf8(exeName.c_str()));

    // A. CPU & I/O Bias
    // 1. Raise I/O Priority to High (3)
    NtWrapper::Initialize(); // Ensure initialized
    IO_PRIORITY_HINT ioPri = static_cast<IO_PRIORITY_HINT>(IoPriorityHigh);
    UniqueHandle hProcTemp(OpenProcessSafe(PROCESS_SET_INFORMATION, pid));
    NtWrapper::SetInformationProcess(hProcTemp.get(), 
                                     ProcessIoPriority, &ioPri, sizeof(ioPri));

    // 2. Raise Process Priority (Bias threads)
    // Cache original for restoration
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid));
    if (hProc) {
        m_lastBoostedPriority = GetPriorityClass(hProc.get());
        if (m_lastBoostedPriority == 0) m_lastBoostedPriority = NORMAL_PRIORITY_CLASS;
        
        // Use ABOVE_NORMAL to give network threads an edge over background/bulk
        SetPriorityClass(hProc.get(), ABOVE_NORMAL_PRIORITY_CLASS);

        // C. Burst-Friendly Scheduling (Disable EcoQoS)
        // Ensure browser threads are never scheduled on E-cores or throttled during bursty loads
        PROCESS_POWER_THROTTLING_STATE powerThrottling = {};
        powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        powerThrottling.StateMask = 0; // 0 = Disable Throttling (High Perf)
        
        NtWrapper::SetInformationProcess(hProc.get(), ProcessPowerThrottling, 
                                         &powerThrottling, sizeof(powerThrottling));
                                         
        Log("[FNRO] Burst Protection (NoEcoQoS) applied to PID: " + std::to_string(pid));
    }

    // B. QoS / DSCP Tagging
    ApplyQosPolicy(exeName);

    m_lastBoostedPid = pid;
    m_lastBoostedBrowser = exeName;
}

void NetworkMonitor::RemoveBrowserBoost() {
    if (m_lastBoostedPid == 0) return;

    Log("[FNRO] Restoring priorities for PID: " + std::to_string(m_lastBoostedPid));

    // A. Restore CPU & I/O
    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION, FALSE, m_lastBoostedPid));
    if (hProc) {
        IO_PRIORITY_HINT ioPri = static_cast<IO_PRIORITY_HINT>(IoPriorityNormal);
        NtWrapper::SetInformationProcess(hProc.get(), ProcessIoPriority, &ioPri, sizeof(ioPri));
        SetPriorityClass(hProc.get(), m_lastBoostedPriority);
    }

    // B. Remove QoS Tag
    if (!m_lastBoostedBrowser.empty()) {
        RemoveQosPolicy(m_lastBoostedBrowser);
    }

    m_lastBoostedPid = 0;
    m_lastBoostedBrowser.clear();
}

void NetworkMonitor::ApplyQosPolicy(const std::wstring& exeName) {
    // Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\<PolicyName>
    std::wstring keyPath = L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\PMan_FNRO_" + exeName;
    
    // Values mandated by Windows Policy-based QoS
    RegWriteString(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Version", L"1.0");
    RegWriteString(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Application Name", exeName);
    RegWriteString(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Protocol", L"*");
    RegWriteString(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"DSCP Value", L"46"); // EF (Expedited Forwarding)
    RegWriteString(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Throttle Rate", L"-1");

    // Note: Changes to Policy-based QoS usually require NLA service refresh or gpupdate.
    // However, direct registry injection often works for new flows on next socket creation.
}

void NetworkMonitor::RemoveQosPolicy(const std::wstring& exeName) {
    std::wstring keyPath = L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\PMan_FNRO_" + exeName;
    RegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, keyPath.c_str());
}

void NetworkMonitor::DeprioritizeBackgroundApps() {
    if (m_areBackgroundAppsThrottled) return;

    Log("[FNRO] Deprioritizing background traffic sources...");

    std::lock_guard lock(m_appsMtx);
    ForEachProcess([this](const PROCESSENTRY32W& pe) {
        std::wstring name = pe.szExeFile;
        asciiLower(name); // Ensure case-insensitive match

        if (m_backgroundApps.count(name)) {
            DWORD pid = pe.th32ProcessID;
            
            UniqueHandle hProc(OpenProcessSafe(PROCESS_SET_INFORMATION, pid));
            if (hProc) {
                // 1. Lower Process Priority (IDLE)
                // This ensures they yield CPU to the browser immediately
                SetPriorityClass(hProc.get(), IDLE_PRIORITY_CLASS);

                // 2. Lower I/O Priority (Very Low)
                // This prevents disk contention during page loads/caching
                IO_PRIORITY_HINT ioPri = static_cast<IO_PRIORITY_HINT>(IoPriorityVeryLow);
                NtWrapper::SetInformationProcess(hProc.get(), ProcessIoPriority, &ioPri, sizeof(ioPri));

                m_throttledPids.insert(pid);
            }
        }
    });

    m_areBackgroundAppsThrottled = true;
}

void NetworkMonitor::RestoreBackgroundApps() {
    if (!m_areBackgroundAppsThrottled) return;

    Log("[FNRO] Restoring background traffic sources...");

    for (DWORD pid : m_throttledPids) {
        UniqueHandle hProc(OpenProcessSafe(PROCESS_SET_INFORMATION, pid));
        if (hProc) {
            // Restore Normal Priorities
            SetPriorityClass(hProc.get(), NORMAL_PRIORITY_CLASS);

            IO_PRIORITY_HINT ioPri = static_cast<IO_PRIORITY_HINT>(IoPriorityNormal);
            NtWrapper::SetInformationProcess(hProc.get(), ProcessIoPriority, &ioPri, sizeof(ioPri));
        }
    }

    m_throttledPids.clear();
    m_areBackgroundAppsThrottled = false;
}

void NetworkMonitor::AttemptAutoRepair() {
    uint64_t now = GetTickCount64();
    
    // Safety Cooldown: Wait 5 minutes between full repair cycles
    if (now - m_lastRepairTime < 300000) return;

    m_repairStage++;
    Log("[NET_REPAIR] Connection dead > 5s. Attempting Auto-Repair Stage " + std::to_string(m_repairStage));

    switch (m_repairStage) {
		case 1:
			Log("[NET_REPAIR] Flushing DNS Cache...");
			ExecuteNetCommand(L"cmd.exe /c ipconfig /flushdns");
			break;

    case 2:
			Log("[NET_REPAIR] Renewing IP Address...");
			ExecuteNetCommand(L"cmd.exe /c ipconfig /release && ipconfig /renew");
			break;

    case 3: // End of cycle
			m_repairStage = 0;
			m_lastRepairTime = now;
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
    // [FIX] C28020: Initialize size to structure header size to satisfy analyzer range check
    DWORD size = sizeof(MIB_TCPTABLE_OWNER_PID);
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
                // [FIX] Relaxed Threshold: >5 is too low for Game Launchers/P2P/Browsers.
                // Modern browsers can easily have 20+ SYN_SENT during page loads or downloads.
                // Only throttle if it looks like a malicious flood (>50).
                if (count > 50) {
                    Log("[NET] Massive Connection Storm detected (PID " + std::to_string(pid) + " count: " + std::to_string(count) + ")");
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
    // [FIX] C6031: Check return value
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        Log("[NET] Warning: CoInitializeEx failed: " + std::to_string(hr));
    }

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

        // =========================================================
        // Adaptive Contention Scoring (FNRO v2)
        // =========================================================
        if (m_foregroundIsInteractive) {
            int score = CalculateContentionScore();
            FnroLevel targetLevel = FnroLevel::Off;

            // Determine FNRO Level based on Score Bands
            if (score >= 70) {
                targetLevel = FnroLevel::Aggressive; // Throttling + Aggressive Defense
            }
            else if (score >= 50) {
                targetLevel = FnroLevel::Active; // Standard Throttling
            }
            else if (score >= 30) {
                targetLevel = FnroLevel::Light; // Priority Bias only
            }

            ApplyFnroLevel(targetLevel);
        }
        else {
            // If user switches to non-interactive app, relax defenses immediately
            ApplyFnroLevel(FnroLevel::Off);
        }

        // Adaptive Polling: 
        // If Unstable/Offline, check frequently (5s) to recover fast.
        // If Stable, check less frequently (30s) to save resources.
        // (For now, fixed 5s as per requirement to detect lag spikes)
        std::unique_lock lock(m_mtx);
        m_cv.wait_for(lock, std::chrono::seconds(5), [this] { return !m_running; });
    }

    CoUninitialize();
}
