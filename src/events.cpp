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

#include "events.h"
#include "etw_monitor.h"						
#include "globals.h"
#include "idle_affinity.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "policy.h"
#include "tweaks.h"
#include "services.h"
#include "executor.h" // For Circuit Breaker (Executor)
#include <objbase.h>
#include <iostream>
#include <vector>
#include <unordered_set>

// [CIRCUIT BREAKER] Track critical system PIDs to detect crashes
static std::unordered_set<DWORD> g_criticalPids;
static std::mutex g_criticalPidsMtx;

// Add static queue limit counter
static std::atomic<int> g_iocpQueueSize{0};
static constexpr int MAX_IOCP_QUEUE_SIZE = 1000;

bool PostIocp(JobType t, DWORD pid, HWND hwnd)
{
    // Atomically reserve slot before allocation
    int currentSize = g_iocpQueueSize.fetch_add(1, std::memory_order_acq_rel);
    if (currentSize >= MAX_IOCP_QUEUE_SIZE)
    {
        g_iocpQueueSize.fetch_sub(1, std::memory_order_release);
        return false; // Drop event, queue full
    }
    
    // Now safe to allocate
    IocpJob* job = new (std::nothrow) IocpJob();
    if (!job) {
        // FIX: Decrement counter if allocation fails, otherwise the slot is leaked forever
        g_iocpQueueSize.fetch_sub(1, std::memory_order_release);
        Log("[IOCP] Failed to allocate job - out of memory");
        return false;
    }
    job->type = t;
    job->pid = pid;
    job->hwnd = hwnd;
    
	// Queue size was already reserved (incremented) at the start of the function.
    // Do NOT increment again here.
    
    if (!PostQueuedCompletionStatus(g_hIocp.get(), 0, 0, reinterpret_cast<LPOVERLAPPED>(job)))
    {
        g_iocpQueueSize.fetch_sub(1, std::memory_order_release);
        delete job;
        Log("[IOCP] Post failed, event dropped");
    
        
        DWORD err = GetLastError();
        if (err != ERROR_SUCCESS) {
            Log("[IOCP] PostQueuedCompletionStatus failed: " + std::to_string(err));
        }
        return false;
    }
    
    return true;
}

void PostShutdown()
{
    if (g_hIocp)
        PostQueuedCompletionStatus(g_hIocp.get(), 0, IOCP_SHUTDOWN_KEY, nullptr);
}

void WaitForThreads(DWORD timeoutMs)
{
    std::unique_lock lock(g_shutdownMtx);
    g_shutdownCv.wait_for(lock, std::chrono::milliseconds(timeoutMs), 
                          [] { return g_threadCount.load() == 0; });
    
    if (g_threadCount > 0)
    {
        Log("Warning: " + std::to_string(g_threadCount.load()) + " threads still running");
    }
}

// DpcIsrCallback and EtwCallback moved to etw_monitor.cpp

// EtwThread and StopEtwSession moved to etw_monitor.cpp

void IocpConfigWatcher()
{
    g_threadCount++;
    
    std::filesystem::path cfg = GetLogPath() / CONFIG_FILENAME;
    std::filesystem::path dir = cfg.parent_path();
    
    if (!std::filesystem::exists(dir))
    {
        Log("Config directory doesn't exist: " + WideToUtf8(dir.c_str()));
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }
    
    HANDLE hDir = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (hDir == INVALID_HANDLE_VALUE) 
    { 
        Log("CreateFile watcher failed: " + std::to_string(GetLastError())); 
        g_threadCount--;
        g_shutdownCv.notify_one();
        return; 
    }
    
    if (!g_hIocp)
    {
        CloseHandle(hDir);
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }
    
    HANDLE hPort = CreateIoCompletionPort(hDir, g_hIocp.get(), 0, 0);
    if (!hPort) 
    { 
        CloseHandle(hDir); 
        Log("CreateIoCompletionPort failed");
        g_threadCount--;
        g_shutdownCv.notify_one();
        return; 
    }

    alignas(DWORD) BYTE buf[4096];
    OVERLAPPED ov{};
    
    auto read = [&]() -> BOOL {
        ZeroMemory(&ov, sizeof(ov));
        return ReadDirectoryChangesW(hDir, buf, sizeof(buf), FALSE,
                                     FILE_NOTIFY_CHANGE_LAST_WRITE,
                                     nullptr, &ov, nullptr);
    };
    
    if (!read())
    {
        Log("Initial ReadDirectoryChangesW failed");
        CloseHandle(hDir);
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }
    
    while (g_running)
    {
        DWORD bytes = 0; 
        ULONG_PTR key = 0; 
        LPOVERLAPPED pov = nullptr;
        
        BOOL result = GetQueuedCompletionStatus(g_hIocp.get(), &bytes, &key, &pov, 1000);
        
        if (!result && pov == nullptr)
        {
            continue;
        }
        
        if (key == IOCP_SHUTDOWN_KEY)
        {
            Log("[IOCP] Shutdown signal received - draining queue");
            break;
        }
        
		if (pov)
        {
            if (pov == &ov)
            {
                // Filter events: Only reload if config.ini actually changed
                // This prevents log.txt writes from triggering the debounce timer
                bool configChanged = false;
                
                if (bytes > 0)
                {
					PFILE_NOTIFY_INFORMATION info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buf);
                    BYTE* endOfData = buf + bytes;

                    while (true)
                    {
                        // [FIX] Bounds Check 1: Ensure header fits in buffer
                        if (reinterpret_cast<BYTE*>(info) + sizeof(FILE_NOTIFY_INFORMATION) > endOfData) break;
                        
                        // [FIX] Bounds Check 2: Ensure filename fits in buffer
                        if (reinterpret_cast<BYTE*>(info->FileName) + info->FileNameLength > endOfData) break;

                        std::wstring fileName(info->FileName, info->FileNameLength / sizeof(wchar_t));
						if (ContainsIgnoreCase(fileName, CONFIG_FILENAME) || 
                            ContainsIgnoreCase(fileName, CUSTOM_LAUNCHERS_FILENAME) ||
                            ContainsIgnoreCase(fileName, IGNORED_PROCESSES_FILENAME))
                        {
                            configChanged = true;
                            break;
                        }
                        
                        if (info->NextEntryOffset == 0) break;
                        
                        PFILE_NOTIFY_INFORMATION nextInfo = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(
                            reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
                        
                        // [FIX] Bounds Check 3: Ensure next entry pointer is valid
                        if (reinterpret_cast<BYTE*>(nextInfo) >= endOfData) break;

                        info = nextInfo;
                    }
                }
                else
                {
                    // Buffer overflow or unknown change - safer to reload
                    configChanged = true;
                }

                if (configChanged)
                {
                    g_reloadNow.store(true, std::memory_order_release);
                }
                
                read();
            }
            else
            {
                    // Use unique_ptr with custom deleter for automatic cleanup
                    auto job_deleter = [](IocpJob* j) { 
                        delete j; 
                        g_iocpQueueSize.fetch_sub(1, std::memory_order_relaxed);
                    };
                    
                    std::unique_ptr<IocpJob, decltype(job_deleter)> 
                        job(reinterpret_cast<IocpJob*>(pov), job_deleter);
                    
                    if (job)
                    {
                        switch (job->type)
                        {
                            case JobType::Config:
                                // Enforce session termination on config reload
                                if (g_sessionLocked.load()) {
                                    g_serviceManager.RestoreSessionStates();
                                    g_serviceManager.InvalidateSessionSnapshot();
                                    g_sessionLocked.store(false);
                                    g_lockedGamePid.store(0);
                                    Log("[CONFIG] Session ended immediately due to configuration reload.");
                                }
                                g_reloadNow.store(true, std::memory_order_release);
                                break;
							case JobType::Policy:
                                // EvaluateAndSetPolicy takes ownership of PID/HWND, not the job
                                EvaluateAndSetPolicy(job->pid, job->hwnd);
                                break;
                            case JobType::PerformanceEmergency:
                                // Handle Stutter Emergency
                                g_perfGuardian.TriggerEmergencyBoost(job->pid);
                                break;
                            default:
                                Log("[IOCP] ERROR: Unknown job type encountered");
                                break;
                        }
                    }
                }
        }
    }
    
    CancelIo(hDir);
    CloseHandle(hDir);
    
    // CRITICAL: Drain remaining IOCP jobs to prevent memory leaks
    Log("[IOCP] Draining remaining queued jobs...");
    int drainedJobs = 0;
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED pov = nullptr;
    
	// FIX: Add yield to prevent CPU starvation during drain
	while (GetQueuedCompletionStatus(g_hIocp.get(), &bytes, &key, &pov, 0))
    {
        if (pov && pov != &ov)
        {
            delete reinterpret_cast<IocpJob*>(pov);
            g_iocpQueueSize.fetch_sub(1, std::memory_order_relaxed);
            drainedJobs++;
            
            if (drainedJobs % 100 == 0) Sleep(1); // Yield every 100 items
        }
    }
    
    if (drainedJobs > 0)
    {
        Log("[IOCP] Drained " + std::to_string(drainedJobs) + " orphaned jobs");
    }
    
    g_threadCount--;
    g_shutdownCv.notify_one();
}

void AntiInterferenceWatchdog()
{
    g_threadCount++;
    Log("Anti-Interference Watchdog started (Event-Driven)");

    // Open Registry Key for monitoring
    HKEY hKeyRaw = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl", 
        0, KEY_NOTIFY | KEY_QUERY_VALUE | KEY_SET_VALUE, &hKeyRaw) != ERROR_SUCCESS)
    {
        Log("[WATCHDOG] Failed to open registry key. Aborting watchdog thread.");
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }
    UniqueRegKey hKey(hKeyRaw);

    // Create Event for Registry Notifications
    UniqueHandle hRegEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr)); // Auto-reset
    if (!hRegEvent)
    {
        Log("[WATCHDOG] Failed to create registry event.");
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    // Register initial notification
    if (RegNotifyChangeKeyValue(hKey.get(), TRUE, REG_NOTIFY_CHANGE_LAST_SET, hRegEvent.get(), TRUE) != ERROR_SUCCESS)
    {
        Log("[WATCHDOG] Failed to register initial registry notification.");
    }

    HANDLE handles[] = { g_hShutdownEvent.get(), hRegEvent.get() };
    const DWORD CHECK_INTERVAL_MS = 10000; // 10s heartbeat for health checks
    int gcCycles = 0;

    while (g_running)
    {
        // Wait for Shutdown OR Registry Change OR Timeout (Health/GC)
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, CHECK_INTERVAL_MS);

        if (waitResult == WAIT_OBJECT_0) // Shutdown
        {
            Log("[WATCHDOG] Shutdown signal received.");
            break;
        }
			else if (waitResult == WAIT_OBJECT_0 + 1) // Registry Change
            {
                // Re-arm notification immediately
                RegNotifyChangeKeyValue(hKey.get(), TRUE, REG_NOTIFY_CHANGE_LAST_SET, hRegEvent.get(), TRUE);

                if (g_userPaused.load()) continue;

                // Fix Read atomic state
                uint64_t state = g_policyState.load();
                int currentMode = static_cast<int>(state & 0xFFFFFFFF);
                
                if (currentMode != 0 && g_caps.hasAdminRights)
                {
                    DWORD expectedVal = (currentMode == 1) ? VAL_GAME : VAL_BROWSER;
                DWORD actualVal = GetCurrentPrioritySeparation();

                if (actualVal != 0xFFFFFFFF && actualVal != expectedVal)
                {
                    g_interferenceCount++;
                    if (g_lockPolicy.load())
                    {
                        Log("[INTERFERENCE] External change detected: 0x" + std::to_string(actualVal) + 
                            ". Re-asserting: 0x" + std::to_string(expectedVal));
                        
                        g_cachedRegistryValue.store(0xFFFFFFFF); 
                        SetPrioritySeparation(expectedVal);
                    }
					else
                    {
                        static int lastLogCount = -1;
                        int count = g_interferenceCount.load();
                        if (count % 10 == 0 && count != lastLogCount) 
                        {
                            Log("[INTERFERENCE] Registry changed by external tool. Total events: " + 
                                std::to_string(count) + " (Policy Lock: OFF)");
                            lastLogCount = count;
                        }
                    }
                }
            }
        }
		else if (waitResult == WAIT_TIMEOUT) // Heartbeat
        {
            // 0a. Update BITS Metrics (Background)
            g_serviceManager.UpdateBitsMetrics();

            // 0b. Unified Idle Detection
            // Calculate once to share between Core Parking and Mode Revert logic
            uint64_t idleMs = 0;
            bool isIdleInfoValid = false;
            
            LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
            if (GetLastInputInfo(&lii))
            {
                // [OPTIMIZATION] Use 32-bit modular arithmetic for safe rollover handling.
                // This correctly handles uptimes > 49.7 days without complex branching.
                idleMs = static_cast<uint64_t>(static_cast<DWORD>(GetTickCount64()) - lii.dwTime);
                isIdleInfoValid = true;
            }

            // [INTEGRATION] Idle Core Parking Trigger
            // Park if idle > 30s AND not in Game Mode
            if (isIdleInfoValid) 
            {
                static bool lastIdleState = false;
                // Hardcoded 30s threshold for core parking (separate from revert policy)
                bool currentIdleState = (idleMs >= 30000) && (g_lastMode.load() != MODE_GAME);
                
                if (currentIdleState != lastIdleState) {
                    g_idleAffinityMgr.OnIdleStateChanged(currentIdleState);
                    lastIdleState = currentIdleState;
                }
            }

            // Active Session Monitoring Hook
            if (g_sessionLocked.load()) {
                g_serviceManager.EnforceSessionPolicies();
            }

            // [LOGIC] Idle Revert (Browser Mode Revert)
            if (g_idleRevertEnabled.load() && isIdleInfoValid)
            {
                DWORD thresholdMs = g_idleTimeoutMs.load(); 
                int currentMode = g_lastMode.load();

                // Trigger if NOT already in browser mode and idle time exceeded
                if (currentMode == MODE_GAME && idleMs >= thresholdMs)
                {
                    bool gameIsPresent = false;
                    
                    // Strict check: Is a game actually running?
                    if (g_sessionLocked.load())
                    {
                        DWORD gamePid = g_lockedGamePid.load();
                        if (gamePid != 0)
                        {
                            HANDLE hGame = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
                            if (hGame)
                            {
                                DWORD exitCode = 0;
                                if (GetExitCodeProcess(hGame, &exitCode) && exitCode == STILL_ACTIVE)
                                {
                                    gameIsPresent = true;
                                }
                                CloseHandle(hGame);
                            }
                        }
                    }

                    if (!gameIsPresent)
                    {
                        Log("[IDLE] System idle for " + std::to_string(thresholdMs / 1000) + "s with no game running. Reverting to Browser Mode.");
                        
                        // Apply Browser Mode System Settings
                        if (g_caps.hasAdminRights)
                        {
                            SetPrioritySeparation(VAL_BROWSER);
                            SetNetworkQoS(MODE_BROWSER);
                            SetMemoryCompression(MODE_BROWSER);
                            SetTimerResolution(MODE_BROWSER);
                            SetTimerCoalescingControl(MODE_BROWSER);
                        }
                        
                        // Update State
                        g_lastMode.store(MODE_BROWSER);
                        
                        // Release locks
                        if (g_sessionLocked.load())
                        {
                            g_sessionLocked.store(false);
                            g_lockedGamePid.store(0);
                            ResumeBackgroundServices();
                        }
                    }
                }
            }

            // 1. Health Checks
            if (!g_hIocp || g_hIocp.get() == INVALID_HANDLE_VALUE)
            {
                Log("[HEALTH] CRITICAL: IOCP handle is invalid. Initiating shutdown.");
                g_running = false;
                break;
            }

            // ETW Health Check & Auto-Recovery
            if (g_caps.canUseEtw && g_running)
            {
                EtwMonitor::CheckHealthAndRecover();
            }

            // 2. Garbage Collection (Every ~2 mins -> 12 * 10s)
            gcCycles++;
            if (gcCycles >= 12)
            {
                gcCycles = 0;
                
                // Clean up Working Set Tracking
                {
                    std::lock_guard lock(g_workingSetMtx);
                    int itemsChecked = 0;
                    for (auto it = g_originalWorkingSets.begin(); it != g_originalWorkingSets.end() && itemsChecked < 50; )
                    {
                        itemsChecked++;
                        DWORD exitCode = 0;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                        if (!hProcess || (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE))
                        {
                            if (hProcess) CloseHandle(hProcess);
                            it = g_originalWorkingSets.erase(it);
                        }
                        else
                        {
                            if (hProcess) CloseHandle(hProcess);
                            ++it;
                        }
                    }
                }
                
                // Clean up trim times
                {
                    std::lock_guard lock(g_trimTimeMtx);
                    for (auto it = g_lastTrimTimes.begin(); it != g_lastTrimTimes.end(); )
                    {
                        DWORD exitCode = 0;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                        if (!hProcess || (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE))
                        {
                            if (hProcess) CloseHandle(hProcess);
                            it = g_lastTrimTimes.erase(it);
                        }
                        else
                        {
                            if (hProcess) CloseHandle(hProcess);
                            ++it;
                        }
                    }
                }
                
                // Clean up DPC state
                {
                    std::lock_guard lock(g_dpcStateMtx);
                    for (auto it = g_processesWithBoostDisabled.begin(); it != g_processesWithBoostDisabled.end(); )
                    {
                        DWORD exitCode = 0;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                        if (!hProcess || (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE))
                        {
                            if (hProcess) CloseHandle(hProcess);
                            it = g_processesWithBoostDisabled.erase(it);
                        }
                        else
                        {
                            if (hProcess) CloseHandle(hProcess);
                            ++it;
                        }
                    }
                }
                
                // Clean up Process Hierarchy
                {
                    std::unique_lock lh(g_hierarchyMtx);
                    for (auto it = g_processHierarchy.begin(); it != g_processHierarchy.end(); ) 
                    {
                        if (!IsProcessIdentityValid(it->first)) 
                        {
                            // Remove all children from fast lookup map
                            for (const auto& childId : it->second.children) {
                                g_inheritedGamePids.erase(childId.pid);
                            }
                            it = g_processHierarchy.erase(it);
                        } 
                        else 
                        {
                            ++it;
                        }
                    }
                    
                    if (g_processHierarchy.size() > 2000) {
                        Log("[GC] Hierarchy safety limit reached. Clearing cache.");
                        g_processHierarchy.clear();
                        g_inheritedGamePids.clear();
                    }
                }
            }
        }
        else 
        {
            // Error case (e.g. handle invalid)
            Sleep(1000); 
        }
    } 
    
    g_threadCount--;
    g_shutdownCv.notify_one();
}

void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD evt, HWND hwnd, 
                                  LONG, LONG, DWORD, DWORD)
{
    if (evt != EVENT_SYSTEM_FOREGROUND || !hwnd) return;
    DWORD pid = 0; 
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid) PostIocp(JobType::Policy, pid, hwnd);
}

void RegisterPowerNotifications(HWND hwnd)
{
    if (!hwnd) return;
    
    GUID g1 = { 0x5D3E9A59, 0xE9D5, 0x4B00, 
                {0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x5A, 0xE4, 0x2A} };
    GUID g2 = { 0x245D8541, 0x3943, 0x4422, 
                {0xB0, 0x81, 0xA6, 0x18, 0xAC, 0x3C, 0x9E, 0x8A} };
    
    g_pwr1 = RegisterPowerSettingNotification(hwnd, &g1, DEVICE_NOTIFY_WINDOW_HANDLE);
    g_pwr2 = RegisterPowerSettingNotification(hwnd, &g2, DEVICE_NOTIFY_WINDOW_HANDLE);
    
    if (!g_pwr1 || !g_pwr2)
    {
        Log("Power notification registration failed: " + std::to_string(GetLastError()));
    }
}

void UnregisterPowerNotifications()
{
    if (g_pwr1) { UnregisterPowerSettingNotification(g_pwr1); g_pwr1 = nullptr; }
    if (g_pwr2) { UnregisterPowerSettingNotification(g_pwr2); g_pwr2 = nullptr; }
}

bool CheckForShutdownSignal()
{
    if (!g_hShutdownEvent) return false;
    
    DWORD waitResult = WaitForSingleObject(g_hShutdownEvent.get(), 0);
    if (waitResult == WAIT_OBJECT_0)
    {
        Log("Graceful shutdown signal received via named event");
        return true;
    }
    return false;
}

void PerformGracefulShutdown()
{
    Log("Performing graceful shutdown...");
    
    // [CACHE] Atomic destruction on shutdown
    // Releasing the shared_ptr automatically cleans up the cache if no other threads are using it.
    g_sessionCache.store(nullptr, std::memory_order_release);
    
    EtwMonitor::Stop();
    
    if (g_sessionLocked.load())
    {
        Log("[SERVICE] Shutdown detected during game lock - resuming background services");
        ResumeBackgroundServices();
    }

    {
        std::lock_guard lock(g_workingSetMtx);
        g_originalWorkingSets.clear();
        Log("Cleaned up working set tracking");
    }
    
    if (g_highResTimersActive.load())
    {
        SetTimerCoalescingControl(2); // Re-enable coalescing
    }
    
    {
        std::lock_guard lock(g_dpcStateMtx);
        g_processesWithBoostDisabled.clear();
        Log("Cleaned up DPC/ISR state tracking");
    }
    
    g_serviceManager.Cleanup();
    Log("Service manager cleaned up");
    
    if (g_timerResolutionActive.load() != 0)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
            typedef NTSTATUS (NTAPI *NtSetTimerResolutionPtr)(ULONG, BOOLEAN, PULONG);
            auto pNtSetTimerResolution = 
                reinterpret_cast<NtSetTimerResolutionPtr>(
                    GetProcAddress(ntdll, "NtSetTimerResolution"));
            
            if (pNtSetTimerResolution)
            {
                ULONG original = g_originalTimerResolution.load();
                ULONG actual = 0;
                pNtSetTimerResolution(original, TRUE, &actual);
                Log("Restored timer resolution: " + std::to_string(actual / 10000.0) + "ms");
            }
        }
    }

    if (g_memoryCompressionModified.load() && 
        g_originalMemoryCompression.load() != 0xFFFFFFFF)
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            0, KEY_SET_VALUE, &key) == ERROR_SUCCESS)
        {
            DWORD original = g_originalMemoryCompression.load();
            RegSetValueExW(key, L"StoreCompression", 0, REG_DWORD,
                          reinterpret_cast<const BYTE*>(&original), sizeof(original));
            RegCloseKey(key);
            Log("Restored original memory compression: " + std::to_string(original));
        }
    }
    
    if (g_restoreOnExit.load() && 
        g_originalRegistryValue != 0xFFFFFFFF && 
        g_originalRegistryValue != g_cachedRegistryValue.load())
    {
        Log("Restoring original Win32PrioritySeparation value: 0x" + std::to_string(g_originalRegistryValue));
        SetPrioritySeparation(g_originalRegistryValue);
    }
    
    g_running = false;
    PostShutdown();
    
    WaitForThreads(10000);
}
