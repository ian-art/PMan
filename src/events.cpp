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

bool PostIocp(JobType t, DWORD pid, HWND hwnd)
{
    if (!g_hIocp) return false;
    
    auto* job = new(std::nothrow) IocpJob{ t, pid, hwnd };
    if (!job) return false;
    
    if (!PostQueuedCompletionStatus(g_hIocp, 0, 0, reinterpret_cast<LPOVERLAPPED>(job)))
    {
        delete job;
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
                    if (pid != 0)
                    {
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

static void ForceStopEtwSession()
{
    TRACEHANDLE session = g_etwSession.load();
    if (session == 0) return;
    
    static const wchar_t* SESSION_NAME = L"PriorityMgrPrivateSession";
    
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + ((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));
    std::vector<BYTE> buffer(propsSize);
    ZeroMemory(buffer.data(), buffer.size());
    
    PEVENT_TRACE_PROPERTIES props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    ULONG status = ControlTraceW(session, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    if (status == ERROR_SUCCESS)
    {
        Log("[ETW] Session stopped for shutdown");
    }
    else if (status == ERROR_WMI_INSTANCE_NOT_FOUND)
    {
        Log("[ETW] Session already stopped");
    }
    else
    {
        Log("[ETW] Stop failed: " + std::to_string(status));
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

    TRACEHANDLE hTrace = OpenTraceW(&t);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        Log("ETW: OpenTrace failed: " + std::to_string(GetLastError()));
        ControlTraceW(hSession, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
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
    ControlTraceW(hSession, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    
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
                PostIocp(JobType::Config);
                read();
            }
            else
            {
                std::unique_ptr<IocpJob> job(reinterpret_cast<IocpJob*>(pov));
                if (job)
                {
                    if (job->type == JobType::Config)
                    {
                        g_reloadNow = true;
                    }
                    else if (job->type == JobType::Policy) 
                    { 
                        EvaluateAndSetPolicy(job->pid, job->hwnd); 
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
    Log("Anti-Interference Watchdog started");

    int gcCycles = 0; // Track cycles for garbage collection
    
    while (g_running)
    {
        // Check more frequently if policy locking is enabled (10s vs 30s)
        int checkInterval = g_lockPolicy.load() ? 10 : 30;
        for (int i = 0; i < checkInterval && g_running; ++i) Sleep(1000);
        if (!g_running) break;

        int currentMode = g_lastMode.load();
        if (currentMode == 0) continue;
        if (!g_caps.hasAdminRights) continue;

        DWORD expectedVal = (currentMode == 1) ? VAL_GAME : VAL_BROWSER;
        // Helper to get current needed here or we include tweaks
        // We included tweaks.h, so we can use SetPrioritySeparation, 
        // but getting current separation is inside tweaks.cpp as a static helper.
        // For now, we rely on VerifyPrioritySeparation logic or re-implement read.
        // Actually, let's just use SetPrioritySeparation if we suspect change, 
        // but we need to READ it first to avoid spam. 
        // We will move GetCurrentPrioritySeparation to a shared header or rely on simple reg read here.
        
        DWORD actualVal = 0xFFFFFFFF;
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl", 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
            DWORD val = 0;
            DWORD size = sizeof(val);
            if (RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size) == ERROR_SUCCESS) {
                actualVal = val;
            }
            RegCloseKey(key);
        }

        if (actualVal != 0xFFFFFFFF && actualVal != expectedVal)
        {
            g_interferenceCount++;
            
            if (g_lockPolicy.load())
            {
                Log("[INTERFERENCE] External tool changed registry to 0x" + std::to_string(actualVal) + 
                    ". Re-asserting: 0x" + std::to_string(expectedVal));
                
                g_cachedRegistryValue.store(0xFFFFFFFF); 
                SetPrioritySeparation(expectedVal);
            }
            else
            {
                static bool warnedOnce = false;
                if (!warnedOnce || (g_interferenceCount % 10 == 0)) 
                {
                    Log("[INTERFERENCE] External tool changed registry. 'lock_policy' is OFF.");
                    warnedOnce = true;
                }
            }
        }
        
        // Garbage collection for zombie PIDs (every 2 minutes)
        gcCycles++;
        if (gcCycles >= 4) // 4 * 30s = 2 minutes
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