#include "services.h"
#include "globals.h" // For g_suspendUpdatesDuringGames, g_caps, g_servicesSuspended
#include "logger.h"
#include "utils.h"
#include <vector>
#include <string>

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
    QueryServiceConfigW(state.handle, nullptr, 0, &bytesNeeded);
    
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

bool WindowsServiceManager::SuspendService(const std::wstring& serviceName)
{
    std::lock_guard lock(m_mutex);
    
    auto it = m_services.find(serviceName);
    if (it == m_services.end() || !it->second.handle || it->second.isDisabled)
        return false;
    
    ServiceState& state = it->second;
    SERVICE_STATUS status;
    
    if (!QueryServiceStatus(state.handle, &status))
        return false;
    
    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " already stopped");
        return false;
    }
    
    if (status.dwCurrentState != SERVICE_RUNNING)
    {
        Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " in state: " + 
            std::to_string(status.dwCurrentState) + " - skipping");
        return false;
    }
    
    // Try to pause first (preferred for BITS)
    if (status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE)
    {
        if (ControlService(state.handle, SERVICE_CONTROL_PAUSE, &status))
        {
            state.action = ServiceAction::Paused;
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " paused successfully");
            m_anythingSuspended = true;
            return true;
        }
    }
    
    // Fallback to stop
    if (ControlService(state.handle, SERVICE_CONTROL_STOP, &status))
    {
        // Wait for service to stop (max 5 seconds)
        for (int i = 0; i < 50 && status.dwCurrentState != SERVICE_STOPPED; ++i)
        {
            Sleep(100);
            if (!QueryServiceStatus(state.handle, &status)) break;
        }
        
        state.action = ServiceAction::Stopped;
        m_anythingSuspended = true;
        
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " stopped successfully");
        }
        else
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " stop initiated");
        }
        return true;
    }
    
    DWORD err = GetLastError();
    Log("[SERVICE] Failed to suspend " + WideToUtf8(serviceName.c_str()) + 
        ": " + std::to_string(err));
    return false;
}

bool WindowsServiceManager::ResumeService(const std::wstring& serviceName)
{
    std::lock_guard lock(m_mutex);
    
    auto it = m_services.find(serviceName);
    if (it == m_services.end() || !it->second.handle || it->second.isDisabled)
        return false;
    
    ServiceState& state = it->second;
    
    if (state.action == ServiceAction::None)
        return false; // We didn't suspend it
    
    bool success = false;
    
    if (state.action == ServiceAction::Stopped)
    {
        if (StartServiceW(state.handle, 0, nullptr))
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " started successfully");
            success = true;
        }
        else
        {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING)
            {
                Log("[SERVICE] Failed to start " + WideToUtf8(serviceName.c_str()) + 
                    ": " + std::to_string(err));
            }
            else
            {
                success = true; // Already running is fine
            }
        }
    }
    else if (state.action == ServiceAction::Paused)
    {
        SERVICE_STATUS status;
        if (ControlService(state.handle, SERVICE_CONTROL_CONTINUE, &status))
        {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " resumed successfully");
            success = true;
        }
        else
        {
            Log("[SERVICE] Failed to resume " + WideToUtf8(serviceName.c_str()) + 
                ": " + std::to_string(GetLastError()));
        }
    }
    
    if (success)
    {
        state.action = ServiceAction::None;
    }
    
    return success;
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
        if (state.action != ServiceAction::None)
        {
            // Unlock for ResumeService (it locks internally)
            m_mutex.unlock();
            ResumeService(name);
            m_mutex.lock();
        }
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