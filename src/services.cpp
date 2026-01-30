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
#include <sstream>
#include <unordered_set>
#include <algorithm>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")

// [PATCH] Reduced to 2s to prevent blocking Game Mode activation
static constexpr int SERVICE_OP_WAIT_RETRIES = 20;
static constexpr int SERVICE_OP_WAIT_DELAY_MS = 100;

// Helper: Check for active dependent services to prevent cascade failures
static bool HasActiveDependents(SC_HANDLE hSvc) {
    DWORD bytesNeeded = 0;
    DWORD count = 0;
    // Check if any services depend on this one and are currently running
    if (!EnumDependentServicesW(hSvc, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count) && 
        GetLastError() == ERROR_MORE_DATA && count > 0) {
        return true; 
    }
    return false;
}

// Destructor
WindowsServiceManager::~WindowsServiceManager() {
    CloseBitsCounters();
    // m_scManager and m_services (via ScHandle) clean up automatically
}

bool WindowsServiceManager::Initialize()
{
    if (m_scManager) return true;
    
    // reset() handles the closure of any existing handle automatically
    m_scManager.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
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
    
    // RAII Wrapper (Using standard ScHandle)
    // .get() is required for raw handle access to C-APIs
    ScHandle safeHandle(OpenServiceW(m_scManager.get(), serviceName.c_str(), accessRights));

    if (!safeHandle)
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
    
    ServiceState state;
	state.isDisabled = false;
	state.action = ServiceAction::None;
	state.originalState = SERVICE_STOPPED;
	// DON'T assign handle yet - we'll move it at the end

	// Check if service is disabled
	DWORD bytesNeeded = 0;
	// FIX: Check return value (C6031)
	if (!QueryServiceConfigW(safeHandle.get(), nullptr, 0, &bytesNeeded)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			// Should not happen for size query, but handling gracefully
			Log("[SERVICE] QueryServiceConfigW size check failed: " + std::to_string(GetLastError()));
		}
	}

	std::vector<BYTE> configBuffer(bytesNeeded);
	LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());

	if (QueryServiceConfigW(safeHandle.get(), config, bytesNeeded, &bytesNeeded))
	{
		if (config->dwStartType == SERVICE_DISABLED)
		{
			state.isDisabled = true;
			Log("[SERVICE] Service '" + WideToUtf8(serviceName.c_str()) + "' is disabled - will skip");
			// Transfer ownership even for disabled services (for proper cleanup)
			state.handle = std::move(safeHandle);
			m_services[serviceName] = std::move(state);
			return false;
		}
	}

	// Query original state
	SERVICE_STATUS status;
	if (QueryServiceStatus(safeHandle.get(), &status))
	{
		state.originalState = status.dwCurrentState;
	}

	// Transfer ownership to state object (Move Semantics)
	state.handle = std::move(safeHandle);
	m_services[serviceName] = std::move(state);
	Log("[SERVICE] Added service: " + WideToUtf8(serviceName.c_str()));
	return true;
	}

bool WindowsServiceManager::IsHardExcluded(const std::wstring& serviceName, DWORD currentState) const
{
    // State-Based Hard Exclusions
    if (currentState != SERVICE_RUNNING) return true;

    // Category-Based Hard Exclusions (LOWERCASE ONLY for safety)
    static const std::unordered_set<std::wstring> HARD_EXCLUSIONS = {
        // RPC / DCOM / MMCSS
        L"rpcss", L"dcomlaunch", L"rpceptmapper", L"mmcss",
        // Audio
        L"audiosrv", L"audioendpointbuilder",
        // Input
        L"tabletinputservice", L"hidserv", L"textinputmanagementservice",
        // Power & Thermal
        L"power",
        // Core Networking
        L"nlasvc", L"nsi", L"dhcp", L"dnscache", L"netprofm",
        // SCM Critical
        L"plugplay", L"keyiso", L"samss", L"lsm"
    };

    // Normalize input to lowercase for case-insensitive check
    std::wstring lowerName = serviceName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    if (HARD_EXCLUSIONS.count(lowerName)) return true;

    // Substring checks for broader categories (GPU, Drivers)
    // lowerName already normalized above, reuse it

    if (lowerName.find(L"nvidia") != std::wstring::npos || 
        lowerName.find(L"amd") != std::wstring::npos || 
        lowerName.find(L"intel") != std::wstring::npos) {
        // GPU/Driver related
        return true; 
    }

    return false;
}

// Hard Exclusions (Non-Negotiable)
bool WindowsServiceManager::IsHardExcluded(const std::wstring& serviceName) const
{
    // [FIX] Use lowercase-only set to prevent case-sensitivity bypass
    static const std::unordered_set<std::wstring> HARD_EXCLUSIONS = {
        // RPC / DCOM / MMCSS
        L"rpcss", L"dcomlaunch", L"rpceptmapper", L"mmcss",
        // Audio & Input
        L"audiosrv", L"audioendpointbuilder", L"tabletinputservice", L"hidserv",
        // Power & Thermal
        L"power",
        // Core Networking
        L"nlasvc", L"nsi", L"dhcp", L"dnscache", L"netprofm",
        // SCM Critical
        L"plugplay", L"keyiso", L"samss", L"lsm"
    };

    std::wstring lowerName = serviceName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    if (HARD_EXCLUSIONS.count(lowerName)) return true;

    // Substring checks for Driver/GPU services
    if (lowerName.find(L"nvidia") != std::wstring::npos || 
        lowerName.find(L"amd") != std::wstring::npos || 
        lowerName.find(L"intel") != std::wstring::npos) {
        return true; 
    }

    return false;
}

// Service Enumeration & Eligibility Snapshot
bool WindowsServiceManager::CaptureSessionSnapshot()
{
    std::lock_guard lock(m_mutex);
    
    m_sessionServices.clear();

    if (!m_scManager && !Initialize()) return false;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // FIX: Use SERVICE_STATE_ALL to enumerate all services, then filter by RUNNING
    if (!EnumServicesStatusExW(m_scManager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, 
        SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr))
    {
        DWORD err = GetLastError();
        if (err != ERROR_MORE_DATA) {
            Log("[SERVICE] Snapshot enumeration failed (Size Query): " + std::to_string(err));
            return false;
        }
    }

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

    if (!EnumServicesStatusExW(m_scManager.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded, 
        &servicesReturned, &resumeHandle, nullptr)) {
        Log("[SERVICE] Snapshot failed: Enum error " + std::to_string(GetLastError()));
        return false;
    }

    // [FIX] Pass 1: Identify PIDs that host CRITICAL services (The "Taint" Check)
    // Because of SvcHost Collapse, we must NEVER touch a process if it touches a critical service.
    std::unordered_set<DWORD> taintedPids;
    for (DWORD i = 0; i < servicesReturned; i++) {
        if (IsHardExcluded(services[i].lpServiceName)) {
            taintedPids.insert(services[i].ServiceStatusProcess.dwProcessId);
        }
    }

    // Pass 2: Eligibility Filter - Only process RUNNING services that are NOT tainted
    for (DWORD i = 0; i < servicesReturned; i++) {
        std::wstring name = services[i].lpServiceName;
        DWORD currentState = services[i].ServiceStatusProcess.dwCurrentState;
        DWORD pid = services[i].ServiceStatusProcess.dwProcessId;
        
        // FIX: Explicitly check for RUNNING state since we enumerated ALL
        if (currentState != SERVICE_RUNNING) continue;
        
        // "PID is valid"
        if (pid == 0) continue;

        // [SAFETY] Critical Fix: If this PID hosts a critical service (DNS, DHCP, Audio), skip it entirely.
        if (taintedPids.count(pid)) {
            // Log("[SERVICE] Skipped mixed-process PID " + std::to_string(pid) + " (Hosted Critical Service)");
            continue;
        }

        // Standard exclusion check (still needed for standalone services)
        if (IsHardExcluded(name)) continue;

        ServiceSessionEntry entry;
        entry.name = name;
        entry.pid = pid;
        entry.originalPriority = 0;
        entry.originalAffinity = 0;
        entry.isModified = false;
        
        m_sessionServices.push_back(entry);
    }

    Log("[SERVICE] Session Snapshot Taken. Eligible Services: " + std::to_string(m_sessionServices.size()));
    return true;
}

// Allowlist Resolution
bool WindowsServiceManager::ResolveAllowlist()
{
    std::lock_guard lock(m_mutex);
    if (m_sessionServices.empty()) return false;

    // "Prefer: Telemetry, Indexers, OEM background agents, Third-party updaters"
    // STORE AS LOWERCASE for case-insensitive matching
    static const std::unordered_set<std::wstring> EXACT_ALLOWLIST = {
        // Telemetry & Diagnostics
        L"diagtrack", L"dmwappushservice", L"wersvc", 
        // Indexers & Cache
        L"wsearch", L"sysmain", 
        // Windows Updates (Safe to throttle during game)
        L"wuauserv", L"bits", L"dosvc",
        // Common Third-Party
        L"clicktorunsvc", // Office
        L"steam client service", L"origin web helper service"
    };

    auto it = m_sessionServices.begin();
    while (it != m_sessionServices.end()) {
        bool keep = false;
        std::wstring name = it->name;
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        // 1. Exact Match (Case-Insensitive)
        if (EXACT_ALLOWLIST.count(lower)) keep = true;

        // 2. Substring Match (Broad Categories)
        if (!keep) {
            // "OEM background agents" (Asus, Dell, HP, etc.)
            if (lower.find(L"asus") != std::wstring::npos ||
                lower.find(L"armoury") != std::wstring::npos || // Asus
                lower.find(L"icue") != std::wstring::npos ||    // Corsair
                lower.find(L"razer") != std::wstring::npos ||   // Razer
                lower.find(L"logi") != std::wstring::npos ||    // Logitech
                lower.find(L"alienware") != std::wstring::npos || // Dell
                lower.find(L"omen") != std::wstring::npos ||    // HP
                lower.find(L"lenovo") != std::wstring::npos ||  // Lenovo
                lower.find(L"vantage") != std::wstring::npos ||
                lower.find(L"msi") != std::wstring::npos ||
                lower.find(L"dragon") != std::wstring::npos) {
                keep = true;
            }
            // "Third-party updaters"
            else if (lower.find(L"update") != std::wstring::npos ||
                     lower.find(L"install") != std::wstring::npos ||
                     lower.find(L"helper") != std::wstring::npos ||
                     lower.find(L"agent") != std::wstring::npos ||
                     lower.find(L"telemetry") != std::wstring::npos) {
                 // Safety Check: Ensure we didn't accidentally catch a critical service
                 // (Double-check against Hard Exclusions just in case, though Phase 3 handled it)
                 if (!IsHardExcluded(name)) {
                     keep = true;
                 }
            }
        }

        if (keep) {
            ++it;
        } else {
            it = m_sessionServices.erase(it);
        }
    }

    if (m_sessionServices.empty()) {
        Log("[SERVICE] Abort: Allowlist resulted in 0 services.");
        return false;
    }
    
    Log("[SERVICE] Allowlist Resolved. Optimized Targets: " + std::to_string(m_sessionServices.size()));
    return true;
}

// State Snapshot (Mandatory)
bool WindowsServiceManager::SnapshotServiceStates()
{
    std::lock_guard lock(m_mutex);
    if (m_sessionServices.empty()) return false;

    Log("[SERVICE] Beginning State Snapshot...");

    // Iterate backwards to allow safe removal of failed entries
    for (int i = static_cast<int>(m_sessionServices.size()) - 1; i >= 0; --i) {
        auto& entry = m_sessionServices[i];
        
        // Needs PROCESS_QUERY_INFORMATION for Affinity
        UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.pid));
        bool snapshotOk = false;

        if (hProcess) {
            DWORD_PTR processAffinity = 0;
            DWORD_PTR systemAffinity = 0;
            
            if (GetProcessAffinityMask(hProcess.get(), &processAffinity, &systemAffinity)) {
                DWORD priority = GetPriorityClass(hProcess.get());
                if (priority != 0) {
                    
                    // Capture Session ID (Restored Logic)
                    DWORD sessionId = 0;
                    if (!ProcessIdToSessionId(entry.pid, &sessionId)) {
                         sessionId = 0;
                    }

                    entry.originalAffinity = processAffinity;
                    entry.originalPriority = priority;
                    entry.sessionId = sessionId;
                    entry.timestamp = GetTickCount64();

                    // Prerequisite: Capture Creation Time (TOCTOU Fix)
                    FILETIME ftCreate, ftExit, ftKernel, ftUser;
                    if (GetProcessTimes(hProcess.get(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                        entry.creationTime = (static_cast<uint64_t>(ftCreate.dwHighDateTime) << 32) | ftCreate.dwLowDateTime;
                        snapshotOk = true;
                    }
                }
            }
        }
        
        if (!snapshotOk) {
            Log("[SERVICE] Warning: Snapshot failed for PID " + std::to_string(entry.pid) + 
                ". Removed from eligibility.");
            m_sessionServices.erase(m_sessionServices.begin() + i);
        }
    }
    
    // Abort only if ALL services failed
    if (m_sessionServices.empty()) {
        Log("[SERVICE] Abort: No services could be snapshotted.");
        return false;
    }

    Log("[SERVICE] State Snapshot Complete. All targets captured successfully.");
    return true;
}

// Active Session Monitoring
void WindowsServiceManager::EnforceSessionPolicies()
{
    std::lock_guard lock(m_mutex);
    if (m_sessionServices.empty()) return;

    for (auto& entry : m_sessionServices) {
    if (!entry.isModified) continue;

    bool violation = false;

    UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.pid));
    if (!hProcess) {
        Log("[SERVICE] ALERT: Service violation detected (Process Gone) - " + WideToUtf8(entry.name.c_str()));
        violation = true;
    } else {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(hProcess.get(), &exitCode) && exitCode == STILL_ACTIVE) {
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(hProcess.get(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                uint64_t currentCreateTime = (static_cast<uint64_t>(ftCreate.dwHighDateTime) << 32) | ftCreate.dwLowDateTime;

                if (entry.creationTime != 0 && currentCreateTime != entry.creationTime) {
                     Log("[SERVICE] ALERT: Service violation detected (PID Reused/Restarted) - " + WideToUtf8(entry.name.c_str()));
                     violation = true;
                }
            }
        } else {
            Log("[SERVICE] ALERT: Service violation detected (Exited) - " + WideToUtf8(entry.name.c_str()));
            violation = true;
        }
        // Handle closes automatically
    }

        // "Enforcement Rule: If a service... Restarts/Crashes... It is immediately blacklisted"
        if (violation) {
            // Blacklist: Mark as unmodified so we never touch it again (Apply/Restore will skip it)
            entry.isModified = false; 
            
            // "And restored": Implicit. 
            // 1. If crashed, it's gone. Nothing to restore.
            // 2. If restarted, it's a new process with default affinity. We just ensure we don't re-apply optimizations.
            Log("[SERVICE] Enforcement: Service " + WideToUtf8(entry.name.c_str()) + " removed from session management.");
        }
    }
}

// Phase 6: Apply Optimization (Strict Order)
bool WindowsServiceManager::ApplySessionOptimizations(DWORD_PTR targetAffinityMask)
{
    std::lock_guard lock(m_mutex);
    if (m_sessionServices.empty()) return true; // Nothing to do is a success
    
    // Safety Override: Cannot optimize if target mask is invalid (0)
    if (targetAffinityMask == 0) {
        Log("[SERVICE] Optimization Aborted: Invalid target affinity mask.");
        return false;
    }

    std::ostringstream hexStream;
    hexStream << std::hex << std::uppercase << targetAffinityMask;
    
    Log("[SERVICE] Applying Session Optimizations (Target Affinity: 0x" + 
        hexStream.str() + ")...");

    for (auto& entry : m_sessionServices) {
    bool success = false;

    UniqueHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.pid));
    if (hProcess) {
        // [SECURITY] TOCTOU Check: Verify Identity via Creation Time
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcess.get(), &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            uint64_t currentCreateTime = (static_cast<uint64_t>(ftCreate.dwHighDateTime) << 32) | ftCreate.dwLowDateTime;
            if (currentCreateTime != entry.creationTime) {
                Log("[SERVICE] SKIP: PID Reuse detected for " + WideToUtf8(entry.name.c_str()));
                continue; // Skip without marking modified
            }
        } else {
            Log("[SERVICE] SKIP: Failed to verify identity for " + WideToUtf8(entry.name.c_str()));
            continue;
        }

        // 6.1 Apply Affinity FIRST
        if (SetProcessAffinityMask(hProcess.get(), targetAffinityMask)) {

            // 6.2 Apply Priority SECOND
            if (SetPriorityClass(hProcess.get(), BELOW_NORMAL_PRIORITY_CLASS)) {

                // 6.3 Immediate Validation
                DWORD exitCode = 0;
                if (GetExitCodeProcess(hProcess.get(), &exitCode) && exitCode == STILL_ACTIVE) {
                    success = true;
                    entry.isModified = true;
                } else {
                    Log("[SERVICE] Validation Failed: Service died immediately (" + WideToUtf8(entry.name.c_str()) + ")");
                }
            } else {
                 Log("[SERVICE] Failed to set Priority for " + WideToUtf8(entry.name.c_str()));
            }
        } else {
            Log("[SERVICE] Failed to set Affinity for " + WideToUtf8(entry.name.c_str()));
        }
        // Handle closes automatically
    } else {
        // [FIX] Process is gone or protected. Treat as "soft skip" to prevent destroying the whole session.
        Log("[SERVICE] Warning: Skipped PID " + std::to_string(entry.pid) + " (Gone/Access Denied). Continuing...");
        success = true; // Prevent rollback
    }

        // "Failure at any point -> immediate rollback of all services"
        if (!success) {
            Log("[SERVICE] CRITICAL: Optimization step failed. Initiating IMMEDIATE ROLLBACK.");
            // Immediate Rollback using Verified Logic
            Log("[SERVICE] CRITICAL: Optimization step failed. Initiating IMMEDIATE ROLLBACK via internal helper.");
            RestoreSessionStatesLocked();
            
            return false;
        }
    }

    Log("[SERVICE] Optimization Applied Successfully.");
    return true;
}

// Restoration (Critical)
void WindowsServiceManager::RestoreSessionStates()
{
    std::lock_guard lock(m_mutex);
    RestoreSessionStatesLocked();
}

void WindowsServiceManager::RestoreSessionStatesLocked()
{
    if (m_sessionServices.empty()) return;

    Log("[SERVICE] Restoring Service States...");
    int restoredCount = 0;
    int errorCount = 0;

    // Restoration Order
    for (auto& entry : m_sessionServices) {
    if (!entry.isModified) continue;

    UniqueHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, entry.pid));
    if (hProcess) {
        bool success = true;

        if (!SetProcessAffinityMask(hProcess.get(), entry.originalAffinity)) {
            Log("[SERVICE] ERROR: Failed to restore Affinity for " + WideToUtf8(entry.name.c_str()));
            success = false;
        }

        if (!SetPriorityClass(hProcess.get(), entry.originalPriority)) {
            Log("[SERVICE] ERROR: Failed to restore Priority for " + WideToUtf8(entry.name.c_str()));
            success = false;
        }

        if (success) {
            DWORD_PTR processAffinity, systemAffinity;
            DWORD currentPri = GetPriorityClass(hProcess.get());

            if (currentPri != entry.originalPriority) {
                 Log("[SERVICE] VERIFY FAIL: Priority mismatch for " + WideToUtf8(entry.name.c_str()));
                 SetPriorityClass(hProcess.get(), entry.originalPriority);
                 errorCount++;
            }

            if (GetProcessAffinityMask(hProcess.get(), &processAffinity, &systemAffinity)) {
                if (processAffinity != entry.originalAffinity) {
                    Log("[SERVICE] VERIFY FAIL: Affinity mismatch for " + WideToUtf8(entry.name.c_str()));
                    SetProcessAffinityMask(hProcess.get(), entry.originalAffinity);
                    errorCount++;
                }
            }
        }
        restoredCount++;
        // Handle closes automatically
    } else {
            // If process is gone (OpenProcess failed), it is effectively "restored" to the void.
            // We only log if it's an access error on a live process.
            DWORD err = GetLastError();
            if (err != ERROR_INVALID_PARAMETER) { // PID gone
                Log("[SERVICE] Warning: Failed to open PID " + std::to_string(entry.pid) + 
                    " for restoration (" + WideToUtf8(entry.name.c_str()) + ") Err: " + std::to_string(err));
            }
        }
        
        // Mark as clean to prevent double-restoration loops
        entry.isModified = false;
    }

    Log("[SERVICE] Restoration Complete. Restored: " + std::to_string(restoredCount) + 
        (errorCount > 0 ? (" Errors: " + std::to_string(errorCount)) : ""));
}

// Post-Session Cleanup
void WindowsServiceManager::InvalidateSessionSnapshot()
{
    std::lock_guard lock(m_mutex);
    
    // "Invalidate eligibility snapshot"
    m_sessionServices.clear();
    
    // "Clear service state cache" (Implicitly done by clearing vector)
    Log("[SERVICE] Session Snapshot Invalidated.");
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
    
    if (!QueryServiceStatus(state.handle.get(), &status))
        return false;
    
    // Safety: Do not suspend if other active services depend on this one
    if (HasActiveDependents(state.handle.get())) {
        Log("[SEC] Blocked suspend of " + WideToUtf8(serviceName.c_str()) + " (Has active dependents)");
        return false;
    }

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
        if (ControlService(state.handle.get(), SERVICE_CONTROL_PAUSE, &status)) {
            state.action = ServiceAction::Paused;
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " paused successfully");
            m_anythingSuspended.store(true);
            return true;
        }
    }
    
    // Fallback to stop
    if (ControlService(state.handle.get(), SERVICE_CONTROL_STOP, &status)) {
        // Wait for service to stop (max 5 seconds)
        for (int i = 0; i < SERVICE_OP_WAIT_RETRIES && status.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(SERVICE_OP_WAIT_DELAY_MS);
            if (!QueryServiceStatus(state.handle.get(), &status)) break;
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

bool WindowsServiceManager::DisableServicePermanent(const std::wstring& serviceName)
{
    // Service Killer Implementation
    std::lock_guard lock(m_mutex);

    // RAII Handle for Service
    ScHandle hSvc(OpenServiceW(m_scManager.get(), serviceName.c_str(), 
        SERVICE_CHANGE_CONFIG | SERVICE_STOP | SERVICE_QUERY_STATUS));

    if (!hSvc) {
        Log("[SERVICE] Disable failed: Could not open " + WideToUtf8(serviceName.c_str()));
        return false;
    }

    // 1. Reconfigure to Manual Start (SERVICE_DEMAND_START)
    if (!ChangeServiceConfigW(hSvc.get(), SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 
        SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
        Log("[SERVICE] Failed to change config for " + WideToUtf8(serviceName.c_str()) + 
            ": " + std::to_string(GetLastError()));
        return false;
    }

    // 2. Stop the service if running
    SERVICE_STATUS status;
    if (QueryServiceStatus(hSvc.get(), &status) && status.dwCurrentState != SERVICE_STOPPED) {
        if (ControlService(hSvc.get(), SERVICE_CONTROL_STOP, &status)) {
            Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " set to MANUAL and STOPPED.");
            return true;
        }
    } else {
        Log("[SERVICE] " + WideToUtf8(serviceName.c_str()) + " set to MANUAL (Already stopped).");
        return true;
    }

    return true;
}

// Helper to process service resumption without lock recursion
static bool ResumeServiceState(WindowsServiceManager::ServiceState& state, const std::wstring& serviceName)
{
    if (state.action == ServiceAction::None) return false;

    bool success = false;
    DWORD error = 0;

    if (state.action == ServiceAction::Stopped)
    {
        if (StartServiceW(state.handle.get(), 0, nullptr))
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
            if (ControlService(state.handle.get(), SERVICE_CONTROL_CONTINUE, &status)) {
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
    
    // SAFETY: Auto-Resume services if we are shutting down while suspended.
    // This ensures we never leave the user with disabled updates/audio on exit.
    if (m_anythingSuspended)
    {
        Log("[SERVICE] Safety Resume: Restoring suspended services before shutdown...");
        for (auto& [name, state] : m_services)
        {
            // Re-use existing helper (safe since we hold the lock)
            ResumeServiceState(state, name);
        }
        m_anythingSuspended = false;
    }

    // RAII handles cleanup automatically when the map is cleared
    m_services.clear();
    
    // Explicitly release the manager handle
    m_scManager.reset();
	CloseBitsCounters(); // [PATCH] Ensure PDH is closed
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

void WindowsServiceManager::InitBitsCounters()
{
    if (m_pdhQuery) return; // Already initialized

    if (PdhOpenQueryW(nullptr, 0, reinterpret_cast<PDH_HQUERY*>(&m_pdhQuery)) != ERROR_SUCCESS) {
        m_pdhQuery = nullptr;
        return;
    }

    // BITS bytes transferred/sec counter
    const wchar_t* counterPath = L"\\BITS Net Utilization(*)\\Bytes Transferred/sec";

    if (PdhAddCounterW(reinterpret_cast<PDH_HQUERY>(m_pdhQuery), counterPath, 0, 
        reinterpret_cast<PDH_HCOUNTER*>(&m_bitsCounter)) != ERROR_SUCCESS) {
        CloseBitsCounters();
        return;
    }
}

void WindowsServiceManager::CloseBitsCounters()
{
    if (m_pdhQuery) {
        PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_pdhQuery));
        m_pdhQuery = nullptr;
        m_bitsCounter = nullptr;
    }
}

double WindowsServiceManager::GetBitsBandwidthMBps() const
{
    // Non-blocking retrieval of the last known metric
    std::lock_guard lock(m_metricsMtx);
    return m_lastBitsBandwidth;
}

void WindowsServiceManager::UpdateBitsMetrics()
{
    // This function runs on a background thread.
    // [PATCH] Use persistent query handle to avoid overhead
    
    if (!m_pdhQuery) {
        InitBitsCounters();
        if (!m_pdhQuery) return; // Failed to init
    }

    // First sample (PDH requires two samples for rate counters)
    // Note: If the query is kept open, PdhCollectQueryData simply updates the snapshot.
    // For "Rate" counters, we still need a delay between collections if we want an instant readout,
    // OR we can rely on the natural interval of this function call (10s) if we structure it differently.
    // However, to ensure accurate "current" bandwidth without managing global state timestamps, 
    // a short sleep for differential is still safest for this specific counter type.
    
    if (PdhCollectQueryData(reinterpret_cast<PDH_HQUERY>(m_pdhQuery)) == ERROR_SUCCESS) {
        Sleep(100); 

        if (PdhCollectQueryData(reinterpret_cast<PDH_HQUERY>(m_pdhQuery)) == ERROR_SUCCESS) {
            PDH_FMT_COUNTERVALUE value;
            if (PdhGetFormattedCounterValue(reinterpret_cast<PDH_HCOUNTER>(m_bitsCounter), 
                PDH_FMT_LARGE, nullptr, &value) == ERROR_SUCCESS) {
                
                std::lock_guard lock(m_metricsMtx);
                m_lastBitsBandwidth = (value.largeValue / 1024.0 / 1024.0); // Bytes -> MB
            }
        }
    }
}
