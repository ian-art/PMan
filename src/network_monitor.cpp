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
#include <mmsystem.h> // Required for timeBeginPeriod
#include <tlhelp32.h> // Required for Thread32First/Next
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
#pragma comment(lib, "winmm.lib") // Required for timeBeginPeriod
#pragma comment(lib, "qwave.lib") // [FIX] qWave for Ephemeral QoS

#include <qos2.h>
#include <winternl.h> // For NtQuerySystemInformation types

// Minimal definitions for Handle Enumeration
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

NetworkMonitor g_networkMonitor;

NetworkMonitor::~NetworkMonitor() {
    Stop();
}

void NetworkMonitor::Initialize() {
    g_throttleManager.Initialize(); // Init Job Object
    if (m_running.exchange(true)) return;
    
    m_icmpHandle = IcmpCreateFile();

    // [FIX] Initialize qWave (Ephemeral QoS)
    if (!InitializeQwave()) {
        Log("[NET_ERR] Failed to initialize qWave. QoS features may be disabled.");
    }
    
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

    // [SAFETY] qWave Cleanup (Handles close automatically, but we explicit for safety)
    CloseQwaveFlows();
    if (m_qosHandle) {
        QOSCloseHandle(m_qosHandle);
        m_qosHandle = nullptr;
    }

    if (m_icmpHandle != nullptr && m_icmpHandle != INVALID_HANDLE_VALUE) {
        IcmpCloseHandle(m_icmpHandle);
        m_icmpHandle = nullptr;
    }

    // Telemetry Report
    Log("[NET_STAT] Session Summary: Interactive Boosts: " + std::to_string(m_statsBoostCount) + 
        ", Contention Interventions: " + std::to_string(m_statsThrottleEvents));

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
    // [FIX] Thread-Safe Caching: Protect against concurrent polling (Tray + Worker)
    static std::mutex s_probeMtx;
    static uint64_t s_lastCheck = 0;
    static bool s_lastResult = false;

    uint64_t now = GetTickCount64();
    {
        std::lock_guard<std::mutex> lock(s_probeMtx);
        if (now - s_lastCheck < 5000) return s_lastResult;
    }

// [FIX] Use persistent handle to prevent winnsi.dll race condition (Crash mitigation)
    if (m_icmpHandle == INVALID_HANDLE_VALUE || m_icmpHandle == nullptr) {
        m_icmpHandle = IcmpCreateFile();
        if (m_icmpHandle == INVALID_HANDLE_VALUE) return false;
    }
    HANDLE hIcmp = m_icmpHandle;

    char sendData[] = "PManProbe";
    // [FIX] Memory Alignment: Use vector<uint64_t> to enforce 8-byte alignment for ICMP structures
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    std::vector<uint64_t> replyBufferAligned((replySize + 7) / 8); 
    
    // Targets: 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google)
    unsigned long targets[] = { 0x01010101, 0x08080808 }; 
    int successCount = 0;
    DWORD totalTime = 0;

    for (unsigned long ip : targets) {
        PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBufferAligned.data();
        
        // [FIX] Increased timeout to 800ms to tolerate bufferbloat during streaming/gaming
        DWORD status = IcmpSendEcho(hIcmp, ip, sendData, sizeof(sendData), 
                                  nullptr, replyBufferAligned.data(), replySize, 800);

        if (status > 0 && reply->Status == IP_SUCCESS) {
            successCount++;
            totalTime += reply->RoundTripTime;
        }
    }

    // Handle is closed automatically by unique_ptr here

    bool result = false;
    if (successCount > 0) {
        m_lastLatencyMs = totalTime / successCount;
        // [FIX] Relax threshold to 600ms. Streaming 4K often spikes ping to 300-500ms.
        result = (m_lastLatencyMs <= 600);
    } else {
        m_lastLatencyMs = 9999; // Treat as effectively offline
        result = false;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_probeMtx);
        s_lastCheck = now;
        s_lastResult = result;
    }
    return result;
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

    // 3. [FIX] Check for Window Scaling (RFC 1323) disablement
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Tcp1323Opts", val)) {
         // 0 = Disabled, 1 = Window Scaling only, 2 = Timestamps only, 3 = Both
         if (val == 0 || val == 2) {
             Log("[NET_WARN] TCP Window Scaling is disabled! High latency connections will be capped.");
             issuesFound = true;
         }
    }

    // 4. [FIX] Check Congestion Control Provider
    // Modern Windows (10/11) should use CUBIC or BBR (server). 'NewReno' is legacy and handles packet loss poorly.
    // Note: This is an admin-level check via PowerShell/NetShell, hard to read via Registry for all templates.
    // We check the global parameter override if it exists.
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"CongestionAlgorithm", val)) {
        // If explicitly set to something other than CUBIC (logic varies), warn.
        // But more importantly, check if ECN is forcefully disabled in registry.
        if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"EnableECN", val)) {
            if (val == 0) Log("[NET_INFO] ECN capability is disabled. Enabling it may reduce bufferbloat.");
        }
    }

    if (!issuesFound) {
        Log("[NET] TCP System Configuration appears healthy.");
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

        // [FIX] Race Condition: Cache old PID to ensure accurate removal
        DWORD oldPid = m_lastBoostedPid;
        if (pid != oldPid) {
            // Level 1: Instant Priority Bias (Always Safe)
            if (oldPid != 0) RemoveBrowserBoost();
            
            // Apply to new PID (Fault tolerance check included inside)
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

bool NetworkMonitor::InitializeQwave() {
    QOS_VERSION version = { 1, 0 };
    return QOSCreateHandle(&version, &m_qosHandle) != FALSE;
}

std::vector<HANDLE> NetworkMonitor::GetProcessSocketHandles(DWORD pid) {
    std::vector<HANDLE> sockets;
    ULONG size = 0x10000;
    std::unique_ptr<BYTE[]> buffer(new BYTE[size]);
    NTSTATUS status;

    // Use NtWrapper to query system handles
    while ((status = NtWrapper::QuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer.get(), size, &size)) == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.reset(new BYTE[size]);
    }

    if (!NT_SUCCESS(status)) return sockets;

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.get();
    UniqueHandle hProcess(OpenProcessSafe(PROCESS_DUP_HANDLE, pid));
    
    if (!hProcess) return sockets;

    // [FIX] Optimization: Dynamically detect the OS-specific ObjectTypeIndex for Sockets (Afd)
    // This allows us to filter out 99% of handles (Events, Mutexes, Keys) before expensive duplication.
    static UCHAR socketTypeIndex = 0;
    if (socketTypeIndex == 0) {
        // Create a dummy socket to learn the type index for this kernel session
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            DWORD myPid = GetCurrentProcessId();
            // Scan the snapshot we already have to find our dummy socket
            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                if (handleInfo->Handles[i].UniqueProcessId == myPid && 
                    (HANDLE)(uintptr_t)handleInfo->Handles[i].HandleValue == (HANDLE)s) {
                    socketTypeIndex = handleInfo->Handles[i].ObjectTypeIndex;
                    break;
                }
            }
            closesocket(s);
        }
    }

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry = handleInfo->Handles[i];
        
        if (entry.UniqueProcessId == pid) {
            // [FIX] Apply Type Filtering
            if (socketTypeIndex != 0 && entry.ObjectTypeIndex != socketTypeIndex) continue;

            // Optimization: Duplicate only confirmed socket candidates
            HANDLE hDup = nullptr;
            if (DuplicateHandle(hProcess.get(), (HANDLE)(uintptr_t)entry.HandleValue, 
                              GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                
                // Verify it's a socket by checking options
                int optVal;
                int optLen = sizeof(optVal);
                if (getsockopt((SOCKET)hDup, SOL_SOCKET, SO_TYPE, (char*)&optVal, &optLen) == 0) {
                    sockets.push_back(hDup); // It's a valid socket
                } else {
                    CloseHandle(hDup); // Not a socket
                }
            }
        }
    }
    return sockets;
}

void NetworkMonitor::ApplyQwaveFlows(DWORD pid, bool isVoip) {
    if (!m_qosHandle) return;

    // [FIX] Refresh Safety: Clear existing flows/handles to ensure we don't accumulate 
    // stale duplicates during periodic refresh cycles.
    CloseQwaveFlows();

    // 1. Get duplicated handles for the target process
    std::vector<HANDLE> targetSockets = GetProcessSocketHandles(pid);
    
    // 2. Apply Flow to each socket
    
    // [STRUCTURAL FIX] Define Policy Struct to hold DSCP configuration
    struct FnroNetworkPolicy {
        QOS_TRAFFIC_TYPE TrafficType;
        DWORD DscpValue;
    };

    FnroNetworkPolicy policy = {};

    if (isVoip) {
        policy.TrafficType = QOSTrafficTypeAudioVideo;
        policy.DscpValue = 46; // EF
    } else {
        // Use ExcellentEffort for responsive traffic (Fixes undefined 'Interactive' enum)
        policy.TrafficType = QOSTrafficTypeExcellentEffort;
        policy.DscpValue = 34; // AF41
    }

    for (HANDLE hSock : targetSockets) {
        QOS_FLOWID flowId = 0;
        // Apply Policy: Use TrafficType from struct. 
        // Note: policy.DscpValue is structurally retained for future QOS_SET_FLOW_DSCP_VALUE implementation.
        if (QOSAddSocketToFlow(m_qosHandle, (SOCKET)hSock, nullptr, policy.TrafficType, QOS_NON_ADAPTIVE_FLOW, &flowId) != FALSE) {
            m_activeQosSockets.push_back(hSock); // Store to keep flow alive
        } else {
            CloseHandle(hSock); // Cleanup if failed
        }
    }
    Log("[FNRO] Applied qWave QoS to " + std::to_string(m_activeQosSockets.size()) + " sockets.");
}

void NetworkMonitor::CloseQwaveFlows() {
    // Closing the duplicated handle automatically notifies QOS to remove the socket from the flow.
    for (HANDLE h : m_activeQosSockets) {
        CloseHandle(h);
    }
    m_activeQosSockets.clear();
}

void NetworkMonitor::BoostProcessThreads(DWORD pid) {
    UniqueHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!hSnapshot) return;

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnapshot.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                // Boost thread to improve input/socket responsiveness
                UniqueHandle hThread(OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID));
                if (hThread) {
                    SetThreadPriority(hThread.get(), THREAD_PRIORITY_ABOVE_NORMAL);
                }
            }
        } while (Thread32Next(hSnapshot.get(), &te));
    }
}

void NetworkMonitor::ApplyBrowserBoost(DWORD pid, const std::wstring& exeName) {
    // [FIX] Auto-Disable on Errors: Check fault counter
    if (m_boostFailures > 3) {
        if (m_currentFnroLevel != FnroLevel::Off) {
            Log("[FNRO_ERR] Too many failures. Disabling FNRO safety.");
            ApplyFnroLevel(FnroLevel::Off);
        }
        return;
    }

    Log("[FNRO] Boosting Network Responsiveness for: " + WideToUtf8(exeName.c_str()));

    // A. CPU & I/O Bias
    NtWrapper::Initialize();
    bool success = true;

    // 1. Raise I/O Priority
    IO_PRIORITY_HINT ioPri = static_cast<IO_PRIORITY_HINT>(IoPriorityHigh);
    UniqueHandle hProcTemp(OpenProcessSafe(PROCESS_SET_INFORMATION, pid));
    if (!hProcTemp || !NtWrapper::SetInformationProcess(hProcTemp.get(), ProcessIoPriority, &ioPri, sizeof(ioPri))) {
        success = false;
    }

    // 2. Raise Process Priority & Disable EcoQoS
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid));
    if (hProc) {
        m_lastBoostedPriority = GetPriorityClass(hProc.get());
        if (m_lastBoostedPriority == 0) m_lastBoostedPriority = NORMAL_PRIORITY_CLASS;
        
        if (!SetPriorityClass(hProc.get(), ABOVE_NORMAL_PRIORITY_CLASS)) success = false;

        PROCESS_POWER_THROTTLING_STATE powerThrottling = {};
        powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        powerThrottling.StateMask = 0; // Disable Throttling
        
        NtWrapper::SetInformationProcess(hProc.get(), ProcessPowerThrottling, &powerThrottling, sizeof(powerThrottling));
        Log("[FNRO] Burst Protection (NoEcoQoS) applied to PID: " + std::to_string(pid));
        
        // [FIX] Apply Thread-Level Bias for immediate responsiveness
        BoostProcessThreads(pid);
        
        // [FIX] Reduce Timer Coalescing Latency
        // Force 1ms timer resolution. This ensures the browser's message loop 
        // wakes up immediately to process incoming network packets.
        // [FIX] Prevent Leak: Only apply if this is a new boost session (pid change).
        // If we are just refreshing sockets for the same PID, the timer is already active.
        if (m_lastBoostedPid != pid) {
            timeBeginPeriod(1);
        }
        
        // Telemetry
        m_statsBoostCount++;
    } else {
        success = false;
    }

    if (!success) m_boostFailures++;
    else m_boostFailures = 0; // Reset on success

    // B. QoS / DSCP Tagging (qWave)
    // Detect if VoIP/RTC for correct traffic classification
    std::wstring lowerName = exeName;
    asciiLower(lowerName);
    bool isVoip = (lowerName.find(L"discord") != std::string::npos || 
                   lowerName.find(L"zoom") != std::string::npos || 
                   lowerName.find(L"teams") != std::string::npos);

    ApplyQwaveFlows(pid, isVoip);

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
        
        // Restore default timer resolution (save battery)
        timeEndPeriod(1);
    }

    // B. Remove QoS Tag (Close Handles)
    CloseQwaveFlows();

    m_lastBoostedPid = 0;
    m_lastBoostedBrowser.clear();
}

// [DEPRECATED] Registry-based QoS removed in favor of qWave (Handle-based)

void NetworkMonitor::DeprioritizeBackgroundApps() {
    if (m_areBackgroundAppsThrottled) return;

    Log("[FNRO] Deprioritizing background traffic sources...");
    m_statsThrottleEvents++; // Record intervention

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
                
                // [FIX] Upload Contention Control
                // We cannot safely touch SO_SNDBUF of foreign processes without drivers.
                // Instead, we apply "EcoQoS" (Efficiency Mode) to background uploaders.
                // This tells the scheduler to defer their work to idle times, 
                // indirectly throttling their network throughput.
                PROCESS_POWER_THROTTLING_STATE ecoQos = {};
                ecoQos.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
                ecoQos.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                ecoQos.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED; // Enable Throttling (Eco Mode)
                
                NtWrapper::SetInformationProcess(hProc.get(), ProcessPowerThrottling, &ecoQos, sizeof(ecoQos));

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
            
            // Remove EcoQoS (Restore full speed)
            PROCESS_POWER_THROTTLING_STATE ecoQos = {};
            ecoQos.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
            ecoQos.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
            ecoQos.StateMask = 0; // Disable Throttling
            
            NtWrapper::SetInformationProcess(hProc.get(), ProcessPowerThrottling, &ecoQos, sizeof(ecoQos));
        }
    }

    m_throttledPids.clear();
    m_areBackgroundAppsThrottled = false;
}

void NetworkMonitor::AttemptAutoRepair() {
    uint64_t now = GetTickCount64();
    
    // Smart Backoff: Base 5 mins * Multiplier (5, 10, 20, 40...)
    uint64_t cooldown = 300000ULL * m_repairBackoffMultiplier;
    
    if (now - m_lastRepairTime < cooldown) return;

    m_repairStage++;
    Log("[NET_REPAIR] Connection dead. Attempting Auto-Repair Stage " + std::to_string(m_repairStage) + 
        " (Next backoff: " + std::to_string(cooldown / 60000) + "m)");

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
            // Increase backoff for next time (Exponential: 1 -> 2 -> 4 -> 8)
            if (m_repairBackoffMultiplier < 12) m_repairBackoffMultiplier *= 2; 
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
    std::unordered_set<DWORD> activePids;
    std::unordered_map<DWORD, int> synSentCounts; // Track pending connections

    // 1. IPv4 Scan
    DWORD size4 = sizeof(MIB_TCPTABLE_OWNER_PID);
    if (GetExtendedTcpTable(nullptr, &size4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer4(size4);
        PMIB_TCPTABLE_OWNER_PID pTable4 = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer4.data());

        if (GetExtendedTcpTable(pTable4, &size4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable4->dwNumEntries; i++) {
                DWORD state = pTable4->table[i].dwState;
                DWORD pid = pTable4->table[i].dwOwningPid;

                if (state == MIB_TCP_STATE_ESTAB) {
                    activePids.insert(pid);
                }
                else if (state == MIB_TCP_STATE_SYN_SENT) {
                    synSentCounts[pid]++;
                }
            }
        }
    }

    // 2. IPv6 Scan (Happy Eyeballs / Modern Web)
    DWORD size6 = sizeof(MIB_TCP6TABLE_OWNER_PID);
    if (GetExtendedTcpTable(nullptr, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer6(size6);
        PMIB_TCP6TABLE_OWNER_PID pTable6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer6.data());

        if (GetExtendedTcpTable(pTable6, &size6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable6->dwNumEntries; i++) {
                if (pTable6->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                    activePids.insert(pTable6->table[i].dwOwningPid);
                }
                // Note: We currently only track SYN floods on IPv4 to save cycles
            }
        }
    }

    // 3. Analyze Storms (IPv4 only for now)
    if (g_networkState.load() == NetworkState::Unstable) {
        for (const auto& [pid, count] : synSentCounts) {
            if (count > 50) {
                Log("[NET] Massive Connection Storm detected (PID " + std::to_string(pid) + " count: " + std::to_string(count) + ")");
                g_throttleManager.TriggerCooldown(pid);
            }
        }
    }

    // 4. Update Global Cache
    std::unique_lock lock(g_netActivityMtx);
    g_activeNetPids = std::move(activePids);
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
                // Connection restored, reset backoff to normal (5 mins)
                m_repairBackoffMultiplier = 1; 
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

        // [FIX] Single Consolidated Refresh Logic
        // Re-scan socket table based on contention level to save CPU.
        // Aggressive/Active: 3s (Need fast reaction for new tabs), Light/Off: 10s.
        uint64_t refreshInterval = (m_currentFnroLevel >= FnroLevel::Active) ? 3000 : 10000;
        
        static uint64_t lastQosRefresh = 0;
        if (now - lastQosRefresh > refreshInterval) {
            std::lock_guard lock(m_mtx); 
            // Only refresh if we are actually in an interactive session
            if (m_foregroundIsInteractive && m_lastBoostedPid != 0) {
                ApplyBrowserBoost(m_lastBoostedPid, m_lastBoostedBrowser);
            }
            lastQosRefresh = now;
        }

        // Adaptive Polling: 
        // If Unstable/Offline, check frequently (5s) to recover fast.
        std::unique_lock lock(m_mtx);
        m_cv.wait_for(lock, std::chrono::seconds(5), [this] { return !m_running; });
    }

    CoUninitialize();
}
