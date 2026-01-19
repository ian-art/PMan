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

#ifndef PMAN_SERVICES_H
#define PMAN_SERVICES_H

#include "types.h"
#include <windows.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <memory> // For std::unique_ptr

// RAII Deleter for Service Handles
struct ScHandleDeleter {
    void operator()(SC_HANDLE h) const {
        if (h) ::CloseServiceHandle(h);
    }
};
using ScHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ScHandleDeleter>;

// Enhanced Service Management Class
class WindowsServiceManager
{
public:
    struct ServiceState
    {
        std::wstring name;
        ScHandle handle; // RAII Managed
        ServiceAction action;
        DWORD originalState;
        bool isDisabled;
        
        ServiceState() : handle(nullptr), action(ServiceAction::None), 
                        originalState(SERVICE_STOPPED), isDisabled(false) {}
    };

    // Eligibility Snapshot Structure
    struct ServiceSessionEntry {
        std::wstring name;
        DWORD pid;
        // Data:
        DWORD originalPriority;
        DWORD_PTR originalAffinity;
        uint64_t timestamp;
        uint64_t creationTime; // Anti-PID-Reuse
        DWORD sessionId; // Windows Session ID (Identity Safety)
        bool isModified;
    };
    
private:
    ScHandle m_scManager; // RAII Managed
	std::unordered_map<std::wstring, ServiceState> m_services;
    std::vector<ServiceSessionEntry> m_sessionServices; // Frozen List
    std::mutex m_mutex;
    std::atomic<bool> m_anythingSuspended;

    // Internal helper that assumes m_mutex is already locked
    void RestoreSessionStatesLocked();
    
public:
    WindowsServiceManager() : m_scManager(nullptr), m_anythingSuspended(false) {}
    
    ~WindowsServiceManager();
    
    bool Initialize();
    // Bypass levels for safety
    enum class BypassMode {
        None,           // Strict: Must be in SAFE_SERVICES (Bloatware list)
        Operational,    // Medium: Bypass SAFE_SERVICES, but enforced CRITICAL_WHITELIST
        Force           // Dangerous: Bypass SAFE_SERVICES (Use with extreme caution)
    };

    bool AddService(const std::wstring& serviceName, DWORD accessRights);
    
    // Suspend with granular bypass control
    bool SuspendService(const std::wstring& serviceName, BypassMode mode = BypassMode::None);
    
    bool ResumeService(const std::wstring& serviceName);

    // Hard Exclusions (Strict Session Safety)
    bool IsHardExcluded(const std::wstring& serviceName, DWORD currentState) const;
    
    // Hard Exclusions
    bool IsHardExcluded(const std::wstring& serviceName) const;

    // Session Snapshot
    // "At session entry only, enumerate all services... The eligibility list is frozen"
    bool CaptureSessionSnapshot();

    // Allowlist Resolution
    // "Apply explicit allowlist... Prefer Telemetry, Indexers, OEM agents"
    bool ResolveAllowlist();

    // State Snapshot (Mandatory)
    // "Store: Original priority, affinity, PID, Timestamp, Session ID... If fail -> Abort"
    bool SnapshotServiceStates();

    // Apply Optimization (Strict Order)
    // "Apply Affinity FIRST, Priority SECOND... Failure -> immediate rollback"
    bool ApplySessionOptimizations(DWORD_PTR targetAffinityMask);

    // Restoration (Critical)
    // "Restore original affinity mask, Restore original priority class"
    void RestoreSessionStates();

    // Active Session Monitoring
    // "Continuously monitor... If a service Restarts/Crashes... Immediately blacklist"
    void EnforceSessionPolicies();

    // Post-Session Cleanup
    void InvalidateSessionSnapshot();
    
    // Check if service is in the "Never Kill" list (Kernel, Network, Audio, etc.)
    bool IsCriticalService(const std::wstring& serviceName) const;
    bool SuspendAll();
    void ResumeAll();
	bool IsAnythingSuspended() const;
    void Cleanup();

	// Metrics
    double GetBitsBandwidthMBps() const;
    void UpdateBitsMetrics();

private:
    mutable std::mutex m_metricsMtx;
    mutable double m_lastBitsBandwidth = 0.0;
    mutable uint64_t m_lastBandwidthQuery = 0;
};

// Global helper functions for service management logic
void SuspendBackgroundServices();
void ResumeBackgroundServices();

// BITS Bandwidth Monitor
double GetBitsBandwidth();

#endif // PMAN_SERVICES_H
