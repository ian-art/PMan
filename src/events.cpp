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
	// FIX: Backpressure mechanism - Wait for queue to drain instead of dropping events
    while (g_iocpQueueSize.load(std::memory_order_acquire) >= MAX_IOCP_QUEUE_SIZE && g_running) {
        Sleep(1);
    }
    
    // Double check running state after wait
    if (!g_running) return false;
    
    if (!g_hIocp || g_hIocp == INVALID_HANDLE_VALUE) return false;
    
    // Use nothrow to prevent crashes on OOM
    IocpJob* job = new (std::nothrow) IocpJob{ t, pid, hwnd };
    if (!job) {
        Log("[IOCP] Failed to allocate job - out of memory");
        return false;
    }
    
	// Increment queue size BEFORE posting
    // Fix: Ensure strict ordering (acq_rel) so increment is visible before job is processed
    g_iocpQueueSize.fetch_add(1, std::memory_order_acq_rel);
    
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

// Microsoft-Windows-DPC
static const GUID DPCGuid = { 0x13976d09, 0x032d, 0x4fd7, { 0x81, 0x0a, 0x44, 0x40, 0x2c, 0x10, 0xe2, 0xc1 } };
// Microsoft-Windows-ISR
static const GUID ISRGuid = { 0x99f948be, 0xb355, 0x4fc8, { 0x88, 0x7c, 0x7f, 0xf4, 0x67, 0x9c, 0x88, 0x4d } };

static void WINAPI DpcIsrCallback(EVENT_RECORD* rec) {
    static std::mutex dpcMtx;
    static std::deque<uint64_t> dpcHistory; // Ring buffer of recent latencies
    
    if (!rec) return;

    DWORD bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    if (bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    TRACE_EVENT_INFO* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    
    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) 
        return;

    // Parse DPC duration (event ID 2 = DPCExec)
    // Note: For DPC (Provider {139...}), Event ID 1=Enter, 2=Leave (Duration)
    if (rec->EventHeader.EventDescriptor.Id == 2) {
        ULONGLONG duration = 0;
        for (DWORD i = 0; i < info->PropertyCount; i++) {
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);
            
            if (propName && wcscmp(propName, L"Duration") == 0) {
                PROPERTY_DATA_DESCRIPTOR desc;
                desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                desc.ArrayIndex = ULONG_MAX;
                desc.Reserved = 0;
                DWORD sz = sizeof(duration);
                
                if (TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, 
                                 reinterpret_cast<BYTE*>(&duration)) == ERROR_SUCCESS) {
                    // duration is in 100ns units, convert to microseconds
                    uint64_t latencyUs = duration / 10;
                    
                    std::lock_guard lock(dpcMtx);
                    dpcHistory.push_back(latencyUs);
                    if (dpcHistory.size() > 100) dpcHistory.pop_front();
                    
                    // Store the 95th percentile as system health metric
                    if (!dpcHistory.empty()) {
                        std::vector<uint64_t> sorted(dpcHistory.begin(), dpcHistory.end());
                        std::sort(sorted.begin(), sorted.end());
                        size_t idx = static_cast<size_t>(sorted.size() * 0.95);
                        if (idx >= sorted.size()) idx = sorted.size() - 1;
                        
                        // FIX: Explicit static_cast to double prevents C4244 warning
                        g_lastDpcLatency.store(static_cast<double>(sorted[idx]), std::memory_order_relaxed);
                    }
                }
                break;
            }
        }
    }
}

// ---------------------------  ETW  ------------------------------------
static void WINAPI EtwCallback(EVENT_RECORD* rec)
{
    if (!rec || !g_running) return;

	// Handle DXGI Present Events (Provider: Microsoft-Windows-DxgKrnl)
    static const GUID DxgKrnlGuid = { 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, DxgKrnlGuid))
    {
        DWORD pid = rec->EventHeader.ProcessId;
        uint64_t timestamp = rec->EventHeader.TimeStamp.QuadPart;
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;

        bool isPresentEvent = false;
        // 46=Present(DX9-11), 60=Overlay, 68=History, 184=Blt(DX11/12), 252=VSync
        if (eventId == 46 || eventId == 60 || eventId == 68 || eventId == 184 || eventId == 252) {
            isPresentEvent = true;
        }
        
        if (isPresentEvent) {
             g_perfGuardian.OnPresentEvent(pid, timestamp);
        }
        return;
    }

    // FIX: DirectX 9 Provider (Microsoft-Windows-Direct3D9)
    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, D3D9Guid))
    {
        // Event 1 = D3D9 Present
        if (rec->EventHeader.EventDescriptor.Id == 1) {
            g_perfGuardian.OnPresentEvent(rec->EventHeader.ProcessId, rec->EventHeader.TimeStamp.QuadPart);
        }
        return;
    }

	// DPC Monitoring (Microsoft-Windows-Kernel-Perf)
	if (IsEqualGUID(rec->EventHeader.ProviderId, DPCGuid) || 
        IsEqualGUID(rec->EventHeader.ProviderId, ISRGuid)) 
    {
        DpcIsrCallback(rec);
        return;
    }

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
        DWORD pid = 0;
        DWORD parentPid = 0;

        for (DWORD i = 0; i < info->PropertyCount; i++)
        {
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);

            if (propName)
            {
                if (wcscmp(propName, L"ProcessID") == 0)
                {
                    PROPERTY_DATA_DESCRIPTOR desc;
                    desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                    desc.ArrayIndex = ULONG_MAX;
                    desc.Reserved = 0;
                    DWORD sz = sizeof(pid);
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, reinterpret_cast<BYTE*>(&pid));
                }
                else if (opcode == 1 && wcscmp(propName, L"ParentProcessID") == 0)
                {
                    PROPERTY_DATA_DESCRIPTOR desc;
                    desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                    desc.ArrayIndex = ULONG_MAX;
                    desc.Reserved = 0;
                    DWORD sz = sizeof(parentPid);
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, reinterpret_cast<BYTE*>(&parentPid));
                }
            }
        }

        if (pid != 0 && g_running)
        {
            g_lastEtwHeartbeat.store(GetTickCount64(), std::memory_order_relaxed);

            if (opcode == 1)
            {
                // Process Start - Build Hierarchy
                ProcessIdentity identity;
                if (GetProcessIdentity(pid, identity)) 
                {
                    std::unique_lock lg(g_hierarchyMtx);
                    
                    ProcessNode node;
                    node.identity = identity;
                    node.inheritedMode = 0;

                    // Link to parent
                    ProcessIdentity parentIdentity;
                    if (parentPid != 0 && GetProcessIdentity(parentPid, parentIdentity)) 
                    {
                        node.parent = parentIdentity;
                        auto it = g_processHierarchy.find(parentIdentity);
                        
                        if (it != g_processHierarchy.end()) 
                        {
                            it->second.children.push_back(identity);
                            
                            // Check inheritance
                            if (it->second.inheritedMode == 1 || g_inheritedGamePids.count(parentPid)) 
                            {
                                node.inheritedMode = 1;
                                g_inheritedGamePids[pid] = identity;
                                Log("[HIERARCHY] Child " + std::to_string(pid) + " inherits GAME mode from " + std::to_string(parentPid));
                            }
                        }
                    }
                    g_processHierarchy[identity] = node;
                }
                
                PostIocp(JobType::Policy, pid);
            }
            else if (opcode == 2)
            {
                // Process End - Cleanup
                CleanupProcessState(pid);
                
                std::unique_lock lg(g_hierarchyMtx);
                g_inheritedGamePids.erase(pid);
                // Note: Complete tree cleanup omitted for safety, relies on periodic GC or restart
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
        // Fix: Ensure handle is valid before storing to prevent race conditions
        if (hSession != 0 && hSession != INVALID_PROCESSTRACE_HANDLE)
        {
            std::lock_guard lock(g_etwSessionMtx);
            g_etwSession.store(hSession);
        }
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

	// Enable DXGI Provider for FPS/Frame Time Monitoring
    // Microsoft-Windows-DxgKrnl: {802ec45a-1e99-4b83-9920-87c98277ba9d}
    // Keyword: 0x1 (Base events including Present)
	static const GUID DxgKrnlGuid = { 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };
	EnableTraceEx2(hSession, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr);

    // FIX: Enable DirectX 9 Provider for older games (C&C3, WoW Classic, etc.)
    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    EnableTraceEx2(hSession, &D3D9Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0xFF, 0, 0, nullptr);

    // FIX: Enable DirectX 10 Provider
    static const GUID D3D10Guid = { 0x9B7E4C8F, 0x342C, 0x4106, { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
    EnableTraceEx2(hSession, &D3D10Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0xFF, 0, 0, nullptr);

	// Enable DPC & ISR Providers (Verbose for duration data))
    status = EnableTraceEx2(hSession, &DPCGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0xFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) Log("ETW: DPC EnableTraceEx2 failed: " + std::to_string(status));

    status = EnableTraceEx2(hSession, &ISRGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0xFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) Log("ETW: ISR EnableTraceEx2 failed: " + std::to_string(status));

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
                // Filter events: Only reload if config.ini actually changed
                // This prevents log.txt writes from triggering the debounce timer
                bool configChanged = false;
                
                if (bytes > 0)
                {
					PFILE_NOTIFY_INFORMATION info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buf);
                    while (true)
                    {
                        std::wstring fileName(info->FileName, info->FileNameLength / sizeof(wchar_t));
						if (ContainsIgnoreCase(fileName, CONFIG_FILENAME) || 
                            ContainsIgnoreCase(fileName, CUSTOM_LAUNCHERS_FILENAME) ||
                            ContainsIgnoreCase(fileName, IGNORED_PROCESSES_FILENAME))
                        {
                            configChanged = true;
                            break;
                        }
                        
                        if (info->NextEntryOffset == 0) break;
                        info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(
                            reinterpret_cast<BYTE*>(info) + info->NextEntryOffset);
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
                    if (currentMode == 1 && idleMs >= thresholdMs)
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
                    // Fix Prevent infinite thread spawning loop (Use atomic to prevent races)
                    static std::atomic<int> retryCount{0};
                    static std::atomic<uint64_t> lastRestartAttempt{0};
                    uint64_t now = GetTickCount64();

                    if (retryCount < 3 && (now - lastRestartAttempt > 5000))
                    {
                        Log("[HEALTH] ETW Session is not running. Restarting (Attempt " + 
                            std::to_string(retryCount + 1) + "/3)...");
                        lastRestartAttempt = now;
                        retryCount++;

                        std::thread restartThread([]() {
                            EtwThread(); 
                        });
                        restartThread.detach();
                    }
                    else if (retryCount >= 3 && (now - lastRestartAttempt > 5000))
                    {
                        // Reset if it's been a long time (e.g. 1 hour), otherwise stay silent
                        if (now - lastRestartAttempt > 3600000) retryCount = 0;
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
                
                // Clean up Process Hierarchy (Leak Protection)
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