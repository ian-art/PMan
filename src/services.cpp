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

#include "services.h"
#include "globals.h" // For g_suspendUpdatesDuringGames, g_caps, g_servicesSuspended
#include "logger.h"
#include "utils.h"
#include <vector>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")

static constexpr int SERVICE_OP_WAIT_RETRIES = 50;
static constexpr int SERVICE_OP_WAIT_DELAY_MS = 100;

WindowsServiceManager::~WindowsServiceManager()
{
    Cleanup();
}

bool WindowsServiceManager::Initialize()
{
    if (m_scManager) return true;
    
    m_scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!m_scManager)
    {
        Log("[SERVICE] Failed to open SC Manager: " + std::to_string(GetLastError()));
        return false;
    }
    
    Log("[SERVICE] Service Manager initialized");
    return true;
}

bool WindowsServiceManager::AddService(const std::wstring& serviceName, DWORD accessRights)
{
    std::lock_guard lock(m_mutex);
    
	if (!m_scManager && !Initialize())
        return false;
    
    // FIX: Explicit null check to satisfy analyzer (C6387)
    if (!m_scManager) return false;

    // Check if already added
    if (m_services.find(serviceName) != m_services.end())
        return true;
    
    ServiceState state;
    state.name = serviceName;
    state.handle = OpenServiceW(m_scManager, serviceName.c_str(), accessRights);
    
    if (!state.handle)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            Log("[SERVICE] Service '" + WideToUtf8(serviceName.c_str()) + "' not found (stripped OS)");
        }
        else
        {
            Log("[SERVICE] Failed to open service '" + WideToUtf8(serviceName.c_str()) + 
                "': " + std::to_string(err));
        }
        return false;
    }
    
	// Check if service is disabled
    DWORD bytesNeeded = 0;
    // FIX: Check return value (C6031)
    if (!QueryServiceConfigW(state.handle, nullptr, 0, &bytesNeeded)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            // Should not happen for size query, but handling gracefully
            Log("[SERVICE] QueryServiceConfigW size check failed: " + std::to_string(GetLastError()));
        }
    }
    
    std::vector<BYTE> configBuffer(bytesNeeded);
    LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());
    
    if (QueryServiceConfigW(state.handle, config, bytesNeeded, &bytesNeeded))
    {
        if (config->dwStartType == SERVICE_DISABLED)
        {
            state.isDisabled = true;
            Log("[SERVICE] Service '" + WideToUtf8(serviceName.c_str()) + "' is disabled - will skip");
            CloseServiceHandle(state.handle);
            state.handle = nullptr;
            m_services[serviceName] = state;
            return false;
        }
    }
    
    // Query original state
    SERVICE_STATUS status;
    if (QueryServiceStatus(state.handle, &status))
    {
        state.originalState = status.dwCurrentState;
    }
    
    m_services[serviceName] = state;
    Log("[SERVICE] Added service: " + WideToUtf8(serviceName.c_str()));
    return true;
}

bool WindowsServiceManager::IsCriticalService(const std::wstring& serviceName) const
{
    // CRITICAL WHITELIST: Services that must NEVER be killed to preserve OS stability
    static const std::unordered_set<std::wstring> CRITICAL_WHITELIST = {
        // --- Core Windows Infrastructure ---
        L"RpcSs", L"RpcEptMapper", L"DcomLaunch", L"LSM", L"SamSs", L"PlugPlay", 
        L"Power", L"SystemEventsBroker", L"TimeBrokerSvc", L"KeyIso", L"CryptSvc", 
        L"ProfSvc", L"SENS", L"Schedule", L"BrokerInfrastructure", L"StateRepository",
        
        // --- Network & Connectivity ---
        L"Dhcp", L"Dnscache", L"NlaSvc", L"Nsi", L"Netman", L"WlanSvc", L"WwanSvc", 
        L"BFE", L"MpsSvc", L"WinHttpAutoProxySvc", L"LanmanWorkstation", L"LanmanServer",
        
        // --- Hardware & Audio ---
        L"Audiosrv", L"AudioEndpointBuilder", L"BthServ", L"BthHFSrv", 
        L"ShellHWDetection", L"Themes", L"FontCache", L"Spooler", L"WiaRpc",
        
        // --- Security & Updates ---
        L"WinDefend", L"MsMpSvc", L"SecurityHealthService", L"Sppsvc", L"AppInfo",
        
        // --- Remote Access ---
        L"TermService", L"UmRdpService"
    };

    if (CRITICAL_WHITELIST.count(serviceName)) return true;

    // Safety: Ignore per-user services (e.g., CDPUserSvc_1a2b3) unless known safe
    if (serviceName.find(L"User_") != std::wstring::npos || 
        serviceName.find(L"_") != std::wstring::npos) { 
        if (serviceName.find(L"CDPUserSvc") != std::wstring::npos) return false;
        if (serviceName.find(L"OneSyncSvc") != std::wstring::npos) return false;
        if (serviceName.find(L"ContactData") != std::wstring::npos) return false;
        return true; // Default safe
    }
    
    return false;
}

bool WindowsServiceManager::SuspendService(const std::wstring& serviceName, BypassMode mode)
{
    // LEVEL 0: Critical Service Protection (Always Active Unless Force)
    if (mode != BypassMode::Force) {
        if (IsCriticalService(serviceName)) {
            Log("[SEC] Blocked attempt to suspend CRITICAL service: " + WideToUtf8(serviceName.c_str()));
            return false;
        }
    }

    // LEVEL 1: Safe Service Whitelist (Only Active in BypassMode::None)
    if (mode == BypassMode::None) {
        static const std::unordered_set<std::wstring> SAFE_SERVICES = {
            L"wuauserv",      // Windows Update
            L"bits",          // Background Intelligent Transfer
            L"dosvc",         // Delivery Optimization
            L"sysmain",       // Superfetch/SysMain
            L"wsearch",       // Windows Search (Disk Indexer)
            L"clicktorunsvc", // Office Updates
            L"windefend"      // Windows Defender (also in critical list)
        };

        std::wstring checkName = serviceName;
        std::transform(checkName.begin(), checkName.end(), checkName.begin(), ::towlower);

        if (SAFE_SERVICES.find(checkName) == SAFE_SERVICES.end()) {
            Log("[SEC] Blocked attempt to suspend non-whitelisted service: " + WideToUtf8(serviceName.c_str()));
            return false;
        }
    }

    // Proceed with service suspension logic
    std::lock_guard lock(m_mutex);
    
    auto it = m_services.find(serviceName);
    if (it == m_services.end() || !it->second.handle || it->second.isDisabled)
        return false;
    
    ServiceState& state = it->second;
    SERVICE_STATUS status;
    
    if (!QueryServiceStatus(state.handle, &status))
        return false;
    
    if (status.dwCurrentState == SERVICE_STOPPED) {
        Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " already stopped");
        return false;
    }
    
    if (status.dwCurrentState != SERVICE_RUNNING) {
        Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " in state: " + 
            std::to_string(status.dwCurrentState) + " - skipping");
        return false;
    }
    
    // Try to pause first (preferred for services like BITS)
    if (status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) {
        if (ControlService(state.handle, SERVICE_CONTROL_PAUSE, &status)) {
            state.action = ServiceAction::Paused;
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " paused successfully");
            m_anythingSuspended.store(true);
            return true;
        }
    }
    
    // Fallback to stop
    if (ControlService(state.handle, SERVICE_CONTROL_STOP, &status)) {
        // Wait for service to stop (max 5 seconds)
        for (int i = 0; i < SERVICE_OP_WAIT_RETRIES && status.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(SERVICE_OP_WAIT_DELAY_MS);
            if (!QueryServiceStatus(state.handle, &status)) break;
        }
        
        state.action = ServiceAction::Stopped;
        m_anythingSuspended.store(true);
        
        if (status.dwCurrentState == SERVICE_STOPPED) {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " stopped successfully");
        } else {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " stop initiated");
        }
        return true;
    }
    
    DWORD err = GetLastError();
    Log("[SERVICE] Failed to suspend " + WideToUtf8(serviceName.c_str()) + 
        ": " + std::to_string(err));
    return false;
}

// Helper to process service resumption without lock recursion
static bool ResumeServiceState(WindowsServiceManager::ServiceState& state, const std::wstring& serviceName)
{
    if (state.action == ServiceAction::None) return false;

    bool success = false;
    DWORD error = 0;

    if (state.action == ServiceAction::Stopped)
    {
        if (StartServiceW(state.handle, 0, nullptr))
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " started successfully");
            success = true;
        }
        else
        {
            error = GetLastError();
            if (error == ERROR_SERVICE_ALREADY_RUNNING)
            {
                success = true;
            }
            else
            {
                Log("[SERVICE] Failed to start " + WideToUtf8(serviceName.c_str()) + 
                    ": " + std::to_string(error));
            }
        }
    }
	else if (state.action == ServiceAction::Paused)
    {
        SERVICE_STATUS status;
        // FIX: Retry loop for service resumption (Claim 7.1)
        // Services may fail transiently if dependencies are busy.
        bool resumed = false;
        for (int attempt = 0; attempt < 3; ++attempt) {
            if (ControlService(state.handle, SERVICE_CONTROL_CONTINUE, &status)) {
                resumed = true;
                break;
            }
            Sleep(500 * (attempt + 1)); // Backoff: 500ms, 1000ms, 1500ms
        }

        if (resumed)
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " resumed successfully");
            success = true;
        }
        else
        {
            error = GetLastError();
            Log("[SERVICE] Failed to resume " + WideToUtf8(serviceName.c_str()) + 
                ": " + std::to_string(error));
        }
    }

#ifdef _DEBUG
    if (!success && error != 0)
    {
        std::wstring msg = L"[SERVICE] Error resuming " + serviceName + L": " + std::to_wstring(error) + L"\n";
        OutputDebugStringW(msg.c_str());
    }
#endif

    if (success)
    {
        state.action = ServiceAction::None;
    }

    return success;
}

bool WindowsServiceManager::ResumeService(const std::wstring& serviceName)
{
    std::lock_guard lock(m_mutex);
    
    auto it = m_services.find(serviceName);
    if (it == m_services.end() || !it->second.handle || it->second.isDisabled)
        return false;
    
    return ResumeServiceState(it->second, serviceName);
}

bool WindowsServiceManager::SuspendAll()
{
    bool anySuccess = false;
    
    for (auto& [name, state] : m_services)
    {
        if (SuspendService(name))
        {
            anySuccess = true;
        }
    }
    
    return anySuccess;
}

void WindowsServiceManager::ResumeAll()
{
    std::lock_guard lock(m_mutex);
    
    if (!m_anythingSuspended)
    {
        Log("[SERVICE] Nothing to resume - no services were suspended");
        return;
    }
    
    Log("[SERVICE] Resuming all suspended services...");
    
    for (auto& [name, state] : m_services)
    {
        ResumeServiceState(state, name);
    }
    
    m_anythingSuspended = false;
    Log("[SERVICE] All services resumed");
}

bool WindowsServiceManager::IsAnythingSuspended() const
{
    return m_anythingSuspended;
}

void WindowsServiceManager::Cleanup()
{
    std::lock_guard lock(m_mutex);
    
    for (auto& [name, state] : m_services)
    {
        if (state.handle)
        {
            CloseServiceHandle(state.handle);
            state.handle = nullptr;
        }
    }
    
    if (m_scManager)
    {
        CloseServiceHandle(m_scManager);
        m_scManager = nullptr;
    }
    
    m_services.clear();
    m_anythingSuspended = false;
}

// --------------------------------------------------------------------------
// GLOBAL HELPER FUNCTIONS
// --------------------------------------------------------------------------

void SuspendBackgroundServices()
{
    if (!g_suspendUpdatesDuringGames.load())
    {
        Log("[SERVICE] Service suspension disabled by config");
        return;
    }
    
    if (!g_caps.hasAdminRights)
    {
        Log("[SERVICE] Missing admin rights - cannot suspend services");
        return;
    }
    
    // Initialize service manager
    if (!g_serviceManager.Initialize())
    {
        Log("[SERVICE] Failed to initialize service manager");
        return;
    }
    
    // Add services to manage
    bool hasAnyService = false;
    
    // [SAFETY PATCH] Removed wuauserv and BITS to prevent OS corruption
    /*
    if (g_serviceManager.AddService(L"wuauserv", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }
    
    if (g_serviceManager.AddService(L"BITS", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }
    */

    // Block Delivery Optimization (The main cause of "Online Lag")
    if (g_serviceManager.AddService(L"dosvc", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }

    // Block Office Background Updates
    if (g_serviceManager.AddService(L"clicktorunsvc", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }

    // [DISK SILENCER] Block Search Indexing to prevent 100% Disk Usage
    if (g_serviceManager.AddService(L"wsearch", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }

    // [DISK SILENCER] Block Superfetch to prevent random RAM compression/paging
    if (g_serviceManager.AddService(L"sysmain", 
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START))
    {
        hasAnyService = true;
    }
    
    if (!hasAnyService)
    {
        Log("[SERVICE] No services available for suspension");
        return;
    }
    
    // Suspend all managed services
	if (g_serviceManager.SuspendAll())
    {
        g_servicesSuspended.store(true);
        Log("[SERVICE] Background services suspended successfully");

        double bw = g_serviceManager.GetBitsBandwidthMBps();
        if (bw > 0.1) {
            Log("[SERVICE] BITS bandwidth was active before suspension: " + std::to_string(bw) + " MB/s");
        }
    }
    else
    {
        Log("[SERVICE] No services required suspension (already stopped)");
    }
}

void ResumeBackgroundServices()
{
    Log("[SERVICE] ResumeBackgroundServices() called");
    
    if (!g_serviceManager.IsAnythingSuspended())
    {
        Log("[SERVICE] Nothing to resume - no services were suspended");
        return;
    }
    
g_serviceManager.ResumeAll();
    g_servicesSuspended.store(false);
}

double WindowsServiceManager::GetBitsBandwidthMBps() const
{
    // Non-blocking retrieval of the last known metric
    std::lock_guard lock(m_metricsMtx);
    return m_lastBitsBandwidth;
}

void WindowsServiceManager::UpdateBitsMetrics()
{
    // This function must be called from a background thread (e.g. Watchdog) 
    // because it contains a necessary sleep for PDH sampling.
    
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER counter = nullptr;

    if (PdhOpenQueryW(nullptr, 0, &query) != ERROR_SUCCESS) return;

    // BITS bytes transferred/sec counter
    const wchar_t* counterPath = L"\\BITS Net Utilization(*)\\Bytes Transferred/sec";

    if (PdhAddCounterW(query, counterPath, 0, &counter) != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        return;
    }

    // First sample
    if (PdhCollectQueryData(query) == ERROR_SUCCESS) {
        // We accept the sleep here because this runs on a worker thread
        Sleep(100); 

        // Second sample
        if (PdhCollectQueryData(query) == ERROR_SUCCESS) {
            PDH_FMT_COUNTERVALUE value;
            if (PdhGetFormattedCounterValue(counter, PDH_FMT_LARGE, nullptr, &value) == ERROR_SUCCESS) {
                std::lock_guard lock(m_metricsMtx);
                m_lastBitsBandwidth = (value.largeValue / 1024.0 / 1024.0); // Bytes -> MB
            }
        }
    }

    PdhCloseQuery(query);
}
