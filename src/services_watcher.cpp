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

#include "services_watcher.h"
#include "services.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include <vector>
#include <algorithm>

void ServiceWatcher::Initialize() {
    Log("[WATCHER] Service Watcher initialized (Mode: Auto-Trim Manual Services)");
}

void ServiceWatcher::OnTick() {
    // Only run if service suspension is allowed by config
    if (!g_suspendUpdatesDuringGames.load()) return;
    
    // Rate limit: Check every 30 seconds
    static uint64_t lastCheck = 0;
    uint64_t now = GetTickCount64();
    if (now - lastCheck < 30000) return; 
    lastCheck = now;

    ScanAndTrimManualServices();
}

bool ServiceWatcher::IsSafeToStop(const std::wstring& name) {
    // CRITICAL WHITELIST: Services that must NEVER be killed even if "Idle"
    // Based on Black Viper's "Safe" Configuration & Windows Internals
    static const std::unordered_set<std::wstring> CRITICAL_WHITELIST = {
        // --- Core Windows Infrastructure ---
        L"RpcSs",              // Remote Procedure Call (RPC) - KILLING THIS BSODs SYSTEM
        L"RpcEptMapper",       // RPC Endpoint Mapper
        L"DcomLaunch",         // DCOM Server Process Launcher
        L"LSM",                // Local Session Manager
        L"SamSs",              // Security Accounts Manager
        L"PlugPlay",           // Plug and Play
        L"Power",              // Power Management
        L"SystemEventsBroker", // System Events Broker
        L"TimeBrokerSvc",      // Time Broker
        L"KeyIso",             // CNG Key Isolation
        L"CryptSvc",           // Cryptographic Services
        L"ProfSvc",            // User Profile Service
        L"SENS",               // System Event Notification Service
        L"Schedule",           // Task Scheduler
        L"BrokerInfrastructure", // Background Tasks Infrastructure
        L"StateRepository",    // State Repository Service (Required for UWP/Start Menu)
        
        // --- Network & Connectivity ---
        L"Dhcp",               // DHCP Client
        L"Dnscache",           // DNS Client
        L"NlaSvc",             // Network Location Awareness
        L"Nsi",                // Network Store Interface
        L"Netman",             // Network Connections
        L"WlanSvc",            // WLAN AutoConfig (WiFi)
        L"WwanSvc",            // WWAN AutoConfig (Cellular)
        L"BFE",                // Base Filtering Engine
        L"MpsSvc",             // Windows Defender Firewall
        L"WinHttpAutoProxySvc",// WinHTTP Web Proxy Auto-Discovery Service
        L"LanmanWorkstation",  // Workstation (SMB/File Sharing)
        L"LanmanServer",       // Server (SMB)
        
        // --- Hardware & Audio ---
        L"Audiosrv",           // Windows Audio
        L"AudioEndpointBuilder",// Windows Audio Endpoint Builder
        L"BthServ",            // Bluetooth Support Service
        L"BthHFSrv",           // Bluetooth Handsfree Service
        L"ShellHWDetection",   // Shell Hardware Detection (Autoplay/Hardware events)
        L"Themes",             // Themes (Killing this breaks UI composition)
        L"FontCache",          // Windows Font Cache Service
        L"Spooler",            // Print Spooler (Keep alive to avoid printing errors)
        L"WiaRpc",             // Still Image Acquisition Events
        
        // --- Security & Updates ---
        L"WinDefend",          // Microsoft Defender Antivirus Service
        L"MsMpSvc",            // Microsoft Defender Antivirus Service (New Name)
        L"SecurityHealthService", // Windows Security Service
        L"Sppsvc",             // Software Protection (Windows Activation)
        L"wuauserv",           // Windows Update (Let SuspendBackgroundServices handle this)
        L"AppInfo",            // Application Information (Required for Admin/UAC)
        
        // --- Remote Access ---
        L"TermService",        // Remote Desktop Services
        L"UmRdpService",       // Remote Desktop Services UserMode Port Redirector
    };

    // Fast lookup
    if (CRITICAL_WHITELIST.count(name)) return false;

    // Safety: Ignore per-user services (e.g., CDPUserSvc_1a2b3, WpnUserService_1a2b3)
    // These are often critical for the current user session (Notifications, Clipboard, etc.)
    if (name.find(L"User_") != std::wstring::npos || 
        name.find(L"_") != std::wstring::npos) { 
        
        // Exception: Known bloatware with suffixes can be killed
        if (name.find(L"CDPUserSvc") != std::wstring::npos) return true; // Connected Devices (High CPU)
        if (name.find(L"OneSyncSvc") != std::wstring::npos) return true; // Outlook Sync
        if (name.find(L"ContactData") != std::wstring::npos) return true;
        
        return false; // Default safe
    }
    
    return true;
}

void ServiceWatcher::ScanAndTrimManualServices() {
    SC_HANDLE hSc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSc) return;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    // First call to get size
    EnumServicesStatusExW(hSc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSc);
        return;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

    if (EnumServicesStatusExW(hSc, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr))
    {
        for (DWORD i = 0; i < servicesReturned; i++) {
            std::wstring svcName = services[i].lpServiceName;
            
            // Optimization: Skip if not running
            if (services[i].ServiceStatusProcess.dwCurrentState != SERVICE_RUNNING) continue;
            
            // Safety: Skip Critical Whitelist
            if (!IsSafeToStop(svcName)) continue;

            // Check Start Type (Is it Manual?)
            SC_HANDLE hSvc = OpenServiceW(hSc, svcName.c_str(), SERVICE_QUERY_CONFIG);
            if (hSvc) {
                DWORD configSize = 0;
                QueryServiceConfigW(hSvc, nullptr, 0, &configSize);
                
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<BYTE> cfgBuf(configSize);
                    LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(cfgBuf.data());
                    
                    if (QueryServiceConfigW(hSvc, config, configSize, &configSize)) {
                        
                        // LOGIC: If Manual (Demand Start) AND Idle -> Stop it
                        if (config->dwStartType == SERVICE_DEMAND_START) {
                            
                            // Check Process Idle State (0% CPU usage history)
                            if (IsProcessIdle(services[i].ServiceStatusProcess.dwProcessId)) {
                                
                                Log("[AUTO-TRIM] Stopping idle manual service: " + WideToUtf8(svcName.c_str()));
                                
                                // Register & Force Kill (using force=true to bypass services.cpp whitelist)
                                if (g_serviceManager.AddService(svcName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP)) {
                                    g_serviceManager.SuspendService(svcName, true); 
                                }
                            }
                        }
                    }
                }
                CloseServiceHandle(hSvc);
            }
        }
    }
    
    CloseServiceHandle(hSc);
}

bool ServiceWatcher::IsProcessIdle(DWORD pid) {
    if (pid == 0) return false;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    bool isIdle = false;

    if (GetProcessTimes(hProc, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
        // Convert to 64-bit
        uint64_t k = ((uint64_t)ftKernel.dwHighDateTime << 32) | ftKernel.dwLowDateTime;
        uint64_t u = ((uint64_t)ftUser.dwHighDateTime << 32) | ftUser.dwLowDateTime;
        
        // HEURISTIC: A service is considered "Idle" if it has consumed negligible CPU time 
        // relative to its life, OR simply has very low total accumulation (started and waiting).
        // 100ms (1,000,000 x 100ns intervals) is a safe threshold for "Done initializing, now waiting".
        if ((k + u) < 1000000) {
            isIdle = true;
        }
    }
    
    CloseHandle(hProc);
    return isIdle;
}
