#include "events.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "policy.h"
#include "tweaks.h"
#include "services.h"
#include <objbase.h>
#include <iostream>
#include <vector>

// Add static queue limit counter
static std::atomic<int> g_iocpQueueSize{0};
static constexpr int MAX_IOCP_QUEUE_SIZE = 1000;

bool PostIocp(JobType t, DWORD pid, HWND hwnd)
{
// Check queue limit before allocation
    int currentSize = g_iocpQueueSize.load(std::memory_order_acquire);
    if (currentSize >= MAX_IOCP_QUEUE_SIZE) {
        static std::atomic<int> overflowLogCount{0};
        if (overflowLogCount.fetch_add(1, std::memory_order_relaxed) % 100 == 0) {
            Log("[IOCP] WARNING: Queue overflow (" + std::to_string(currentSize) + 
                " items), dropping jobs. System may be overloaded.");
        }
        return false;
    }
    
    if (!g_hIocp || g_hIocp == INVALID_HANDLE_VALUE) return false;
    
    // Use nothrow to prevent crashes on OOM
    IocpJob* job = new (std::nothrow) IocpJob{ t, pid, hwnd };
    if (!job) {
        Log("[IOCP] Failed to allocate job - out of memory");
        return false;
    }
    
    // Increment queue size BEFORE posting
    g_iocpQueueSize.fetch_add(1, std::memory_order_release);
    
    if (!PostQueuedCompletionStatus(g_hIocp, 0, 0, reinterpret_cast<LPOVERLAPPED>(job)))
    {
        // Post failed - clean up manually
        g_iocpQueueSize.fetch_sub(1, std::memory_order_release);
        delete job;
        
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING && err != ERROR_SUCCESS) {
            Log("[IOCP] PostQueuedCompletionStatus failed: " + std::to_string(err));
        }
        return false;
    }
    
    return true;
}

void PostShutdown()
{
    if (g_hIocp)
        PostQueuedCompletionStatus(g_hIocp, 0, IOCP_SHUTDOWN_KEY, nullptr);
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

// ---------------------------  ETW  ------------------------------------
static void WINAPI EtwCallback(EVENT_RECORD* rec)
{
    if (!rec || !g_running) return;

    // Opcode 1 = ProcessStart, Opcode 2 = ProcessEnd
    BYTE opcode = rec->EventHeader.EventDescriptor.Opcode;
    
    if (opcode != 1 && opcode != 2) return;

    DWORD bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    
    if (bufferSize == 0) return;

    std::vector<BYTE> buffer(bufferSize);
    TRACE_EVENT_INFO* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());

    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) == ERROR_SUCCESS)
    {
        for (DWORD i = 0; i < info->PropertyCount; i++)
        {
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);

            if (propName && wcscmp(propName, L"ProcessID") == 0)
            {
                PROPERTY_DATA_DESCRIPTOR desc;
                desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                desc.ArrayIndex = ULONG_MAX;
                desc.Reserved = 0;

				DWORD pid = 0;
                DWORD pidSize = sizeof(pid);
                
                if (TdhGetProperty(rec, 0, nullptr, 1, &desc, pidSize, reinterpret_cast<BYTE*>(&pid)) == ERROR_SUCCESS)
                {
                    // Protection against race with ForceStopEtwSession
                    // In a real fix, you might use a shared_mutex or check g_etwSession != 0
                    if (pid != 0 && g_running)
                    {
                        // Phase 3: Update Heartbeat
                        g_lastEtwHeartbeat.store(GetTickCount64(), std::memory_order_relaxed);

                        if (opcode == 1)
                        {
                            // Process started - evaluate for policy
                            PostIocp(JobType::Policy, pid);
                        }
                        else if (opcode == 2)
                        {
                            // Process ended - cleanup resources
                            CleanupProcessState(pid);
                        }
                    }
                }
                break;
            }
        }
    }
}

// RAII Wrapper for ETW Session
struct TraceSessionGuard {
    TRACEHANDLE handle;
    const wchar_t* name;
    
    TraceSessionGuard(TRACEHANDLE h, const wchar_t* n) : handle(h), name(n) {}
    
    ~TraceSessionGuard() {
        if (handle) {
            // Helper to stop trace without external buffer dependency if possible, 
            // but ControlTraceW requires properties structure.
            size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + ((wcslen(name) + 1) * sizeof(wchar_t));
            std::vector<BYTE> buffer(propsSize);
            ZeroMemory(buffer.data(), buffer.size());
            PEVENT_TRACE_PROPERTIES props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
            props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            
            ControlTraceW(handle, name, props, EVENT_TRACE_CONTROL_STOP);
        }
    }
    
    void Release() { handle = 0; }
};

// Mutex to prevent race conditions during session stop/callback
static std::mutex g_etwSessionMtx;

static void ForceStopEtwSession()
{
    std::lock_guard lock(g_etwSessionMtx);
    TRACEHANDLE session = g_etwSession.exchange(0);
    if (session == 0) return;
    
    static const wchar_t* SESSION_NAME = L"PriorityMgrPrivateSession";
    
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + ((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
    std::vector<BYTE> buffer(propsSize, 0);
    
    PEVENT_TRACE_PROPERTIES props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
    props->Wnode.Guid = {0};
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    wcsncpy_s(reinterpret_cast<wchar_t*>(buffer.data() + props->LoggerNameOffset),
              (propsSize - sizeof(EVENT_TRACE_PROPERTIES)) / sizeof(wchar_t),
              SESSION_NAME,
              wcslen(SESSION_NAME));
    
    ULONG status = ControlTraceW(session, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    
    if (status == ERROR_SUCCESS) {
        Log("[ETW] Session stopped successfully");
    } else if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
        Log("[ETW] Session already stopped");
    } else {
        Log("[ETW] Stop failed with error: " + std::to_string(status));
    }
}

void EtwThread()
{
    g_threadCount++;
    CoInitialize(nullptr);

    static const wchar_t* SESSION_NAME = L"PriorityMgrPrivateSession";
    
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + ((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
    std::vector<BYTE> buffer(propsSize);
    ZeroMemory(buffer.data(), buffer.size());

    PEVENT_TRACE_PROPERTIES props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID; 
    props->Wnode.ClientContext = 1;
    props->Wnode.Guid = { 0 };
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE hSession = 0;
    ULONG status = StartTraceW(&hSession, SESSION_NAME, props);
    
    if (status == ERROR_SUCCESS)
    {
        g_etwSession.store(hSession);
    }

    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        Sleep(100);
        status = StartTraceW(&hSession, SESSION_NAME, props);
        if (status == ERROR_SUCCESS)
        {
            g_etwSession.store(hSession);
        }
    }

    if (status != ERROR_SUCCESS)
    {
        Log("ETW: StartTrace failed: " + std::to_string(status));
        CoUninitialize();
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    status = EnableTraceEx2(hSession, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0x10, 0, 0, nullptr);

    if (status != ERROR_SUCCESS)
    {
        Log("ETW: EnableTraceEx2 failed: " + std::to_string(status));
        ControlTraceW(hSession, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        CoUninitialize();
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    Log("ETW: Modern Private Session started successfully.");

EVENT_TRACE_LOGFILEW t{};
    t.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    t.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    t.EventRecordCallback = EtwCallback;

    // Wrap session handle for automatic cleanup
    TraceSessionGuard sessionGuard(hSession, SESSION_NAME);

    TRACEHANDLE hTrace = OpenTraceW(&t);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        Log("ETW: OpenTrace failed: " + std::to_string(GetLastError()));
        // sessionGuard destructor will stop the trace
        CoUninitialize();
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    // ProcessTrace blocks until ControlTraceW stops the session
    ULONG processStatus = ProcessTrace(&hTrace, 1, nullptr, nullptr);
    
    if (processStatus != ERROR_SUCCESS && processStatus != ERROR_CANCELLED)
    {
        Log("[ETW] ProcessTrace returned: " + std::to_string(processStatus));
    }

    CloseTrace(hTrace);
    g_etwSession.store(0);
    
    // Explicitly release if we want to control timing, or let destructor handle it
    // Using destructor ensures cleanup even if exceptions occurred
    
    CoUninitialize();

    g_threadCount--;
    g_shutdownCv.notify_one();
}

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
    
    HANDLE hPort = CreateIoCompletionPort(hDir, g_hIocp, 0, 0);
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
        
        BOOL result = GetQueuedCompletionStatus(g_hIocp, &bytes, &key, &pov, 1000);
        
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
                g_reloadNow.store(true, std::memory_order_release);
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
                                g_reloadNow.store(true, std::memory_order_release);
                                break;
                            case JobType::Policy:
                                // EvaluateAndSetPolicy takes ownership of PID/HWND, not the job
                                EvaluateAndSetPolicy(job->pid, job->hwnd);
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
    
    while (GetQueuedCompletionStatus(g_hIocp, &bytes, &key, &pov, 0))
    {
        if (pov && pov != &ov)
        {
            delete reinterpret_cast<IocpJob*>(pov);
            drainedJobs++;
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

    HANDLE handles[] = { g_hShutdownEvent, hRegEvent.get() };
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

            int currentMode = g_lastMode.load();
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
                        static bool warnedOnce = false;
                        if (!warnedOnce || (g_interferenceCount % 10 == 0)) 
                        {
                            Log("[INTERFERENCE] Registry changed by external tool. 'lock_policy' is OFF.");
                            warnedOnce = true;
                        }
                    }
                }
            }
        }
		else if (waitResult == WAIT_TIMEOUT) // Heartbeat
        {
            // 0. Idle Revert Logic
            if (g_idleRevertEnabled.load())
            {
                LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
                if (GetLastInputInfo(&lii))
                {
                    DWORD idleMs = GetTickCount() - lii.dwTime;
                    DWORD thresholdMs = g_idleTimeoutMs.load(); // Use the parsed MS value
                    int currentMode = g_lastMode.load();

                    // Trigger if NOT already in browser mode (2) and idle time exceeded
                    if (currentMode != 2 && idleMs >= thresholdMs)
                    {
                        bool gameIsPresent = false;
                        
                        // Strict check: Is a game actually running?
                        if (currentMode == 1 && g_sessionLocked.load())
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
                                SetNetworkQoS(2);
                                SetMemoryCompression(2);
                                SetTimerResolution(2);
                                SetTimerCoalescingControl(2);
                            }
                            
                            // Update State
                            g_lastMode.store(2);
                            
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
            }

			// 1. Health Checks
            if (!g_hIocp || g_hIocp == INVALID_HANDLE_VALUE)
            {
                Log("[HEALTH] CRITICAL: IOCP handle is invalid. Initiating shutdown.");
                g_running = false;
                break;
            }

			// ETW Health Check & Auto-Recovery
            if (g_caps.canUseEtw && g_running)
            {
                // Fix: Removed 60s silence timeout.
                // Process events are sporadic; silence does not mean the thread is dead.
                // Only restart if the session handle is invalid (0), meaning the thread actually exited.
                
                if (g_etwSession.load() == 0)
                {
                    // Debounce: Ensure we don't spam restarts if it fails instantly
                    static uint64_t lastRestartAttempt = 0;
                    uint64_t now = GetTickCount64();

                    if (now - lastRestartAttempt > 5000) 
                    {
                        Log("[HEALTH] ETW Session is not running (handle=0). Restarting...");
                        lastRestartAttempt = now;

                        std::thread restartThread([]() {
                            Log("[HEALTH] Spawning new ETW thread...");
                            EtwThread(); 
                        });
                        restartThread.detach();
                    }
                }
            }

            // 2. Garbage Collection (Every ~2 mins -> 12 * 10s)
            gcCycles++;
            if (gcCycles >= 12)
            {
                gcCycles = 0;
                
                // Clean up working set tracking
                {
                    std::lock_guard lock(g_workingSetMtx);
                    for (auto it = g_originalWorkingSets.begin(); it != g_originalWorkingSets.end(); )
                    {
                        DWORD exitCode = 0;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                        if (!hProcess || (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE))
                        {
                            Log("[GC] Removing zombie PID " + std::to_string(it->first) + " from working set map");
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
    
    DWORD waitResult = WaitForSingleObject(g_hShutdownEvent, 0);
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
    
    ForceStopEtwSession();
    
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
            RegSetValueExW(key, L"DisablePagingExecutive", 0, REG_DWORD,
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