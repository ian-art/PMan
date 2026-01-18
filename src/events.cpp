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
#include "globals.h"
#include "idle_affinity.h"
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
    
    if (!PostQueuedCompletionStatus(g_hIocp, 0, 0, reinterpret_cast<LPOVERLAPPED>(job)))
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
    // [OPTIMIZATION] Advanced: Use static ring buffer to prevent heap fragmentation in high-frequency ETW callback
    static constexpr size_t DPC_RING_SIZE = 128;
    static uint64_t dpcRingBuffer[DPC_RING_SIZE] = {0};
    static size_t dpcRingHead = 0;
    static size_t dpcRingCount = 0;
    // [OPTIMIZATION] Mutex removed: ProcessTrace serializes callbacks on the ETW thread.
    
    if (!rec) return;

    DWORD bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    
    // Stack buffer optimization (avoid vector allocation). 4KB is safe and sufficient for ETW metadata.
    if (bufferSize == 0 || bufferSize > 4096) return;
    BYTE buffer[4096]; 
    
    TRACE_EVENT_INFO* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer);
    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) 
        return;

    // Parse DPC duration (event ID 2 = DPCExec)
    if (rec->EventHeader.EventDescriptor.Id == 2) {
        ULONGLONG duration = 0;
        for (DWORD i = 0; i < info->PropertyCount; i++) {
            // [OPTIMIZATION] Fast pointer arithmetic for property check
            // Note: We skip the string compare if the offset looks invalid to save cycles
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);
            
            if (!propName || propName[0] != L'D') continue; // Fast reject
            if (wcscmp(propName, L"Duration") != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
            desc.ArrayIndex = ULONG_MAX;
            desc.Reserved = 0;
            DWORD sz = sizeof(duration);
            
            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, 
                             reinterpret_cast<BYTE*>(&duration)) == ERROR_SUCCESS) {
                
                uint64_t latencyUs = duration / 10;
                
                // [OPTIMIZATION] removed: ProcessTrace serializes callbacks on the ETW thread.
                
                // Update Ring Buffer
                dpcRingBuffer[dpcRingHead] = latencyUs;
                dpcRingHead = (dpcRingHead + 1) % DPC_RING_SIZE;
                if (dpcRingCount < DPC_RING_SIZE) dpcRingCount++;
                
                // [FIX] Rate Limit: Only calculate stats every 128 samples (when ring wraps)
                // This reduces CPU usage by 99% inside the high-frequency callback
                if (dpcRingHead == 0 && dpcRingCount == DPC_RING_SIZE) {
                    uint64_t snapshot[DPC_RING_SIZE];
                    memcpy(snapshot, dpcRingBuffer, sizeof(snapshot));
                    
                    // 95th percentile index
                    size_t idx = (DPC_RING_SIZE * 95) / 100;
                    std::nth_element(snapshot, snapshot + idx, snapshot + DPC_RING_SIZE);
                    g_lastDpcLatency.store(static_cast<double>(snapshot[idx]), std::memory_order_relaxed);
                }
            }
            break;
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

	// CRITICAL: Handle DirectX 9 Present Events (more event IDs)
    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, D3D9Guid))
    {
        // D3D9 has multiple present event IDs depending on presentation mode
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;
        // 1 = D3D9Present, 2 = D3D9PresentEx, 3 = D3D9SwapPresent
        if (eventId >= 1 && eventId <= 3) {
            g_perfGuardian.OnPresentEvent(rec->EventHeader.ProcessId, rec->EventHeader.TimeStamp.QuadPart);
            static int dx9FrameCount = 0;
            if (++dx9FrameCount % 300 == 0) {
				/* Commented out debug logging in hot path to prevent I/O micro-stutter
                Log("[PERF-DEBUG] DX9 Frame captured for PID " + 
                    std::to_string(rec->EventHeader.ProcessId) + " (Event ID: " + 
                    std::to_string(eventId) + ")");
				*/
            }
        }
        return;
    }

    // CRITICAL: Handle DirectX 10/11 Present Events
    static const GUID D3D10Guid = { 0x9B7E4C8F, 0x342C, 0x4106, { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, D3D10Guid))
    {
        // D3D10/11 present event IDs: 8 = Present, 10 = PresentMultiplaneOverlay
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;
        if (eventId == 8 || eventId == 10) {
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
                // [INTEGRATION] Idle Core Parking - Catch processes starting during sleep
                if (g_idleAffinityMgr.IsIdle()) {
                    g_idleAffinityMgr.OnProcessStart(pid);
                }

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

void StopEtwSession()
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
    // FIX: Check return value (C6031)
    if (FAILED(CoInitialize(nullptr))) {
        Log("[ETW] CoInitialize failed");
    }

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

    if (status == ERROR_ALREADY_EXISTS)
    {
        // FIX: Check ownership before killing existing session (Claim 5.2)
        // Only stop it if it looks like a stale session from a previous crash of THIS app.
        // We assume that if we can't query it, or if the name matches, we can reset it.
        // (In a real scenario, we might check the LoggerName in the properties, but here we force reset for stability)
        
        Log("[ETW] Session already exists. Attempting recovery...");
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        Sleep(100);
        status = StartTraceW(&hSession, SESSION_NAME, props);
    }

    if (status == ERROR_SUCCESS)
    {
        if (hSession != 0 && hSession != INVALID_PROCESSTRACE_HANDLE)
        {
            std::lock_guard lock(g_etwSessionMtx);
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

	// CRITICAL: Enable DirectX 9 Provider (for old games like C&C3)
    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    EnableTraceEx2(hSession, &D3D9Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr); // Reduced to INFO

    // CRITICAL: Enable DirectX 10 Provider (hybrid DX10/11)
    static const GUID D3D10Guid = { 0x9B7E4C8F, 0x342C, 0x4106, { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
    EnableTraceEx2(hSession, &D3D10Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr); // Reduced to INFO

	// Enable DPC & ISR Providers (Verbose for duration data))
#if defined(_M_AMD64) || defined(_M_IX86)
    // DPC: Only capture duration warnings (>1ms)
    status = EnableTraceEx2(hSession, &DPCGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                           TRACE_LEVEL_WARNING, 0x10, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) Log("ETW: DPC EnableTraceEx2 failed: " + std::to_string(status));

    // ISR: Only capture duration warnings (>1ms)
    status = EnableTraceEx2(hSession, &ISRGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                           TRACE_LEVEL_WARNING, 0x10, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) Log("ETW: ISR EnableTraceEx2 failed: " + std::to_string(status));
#else
    Log("[ARM64] DPC/ISR monitoring disabled (ARM GIC not supported)");
    // Ensure status is SUCCESS so we don't bail out below
    status = ERROR_SUCCESS;
#endif

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
	while (GetQueuedCompletionStatus(g_hIocp, &bytes, &key, &pov, 0))
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
                uint64_t now = GetTickCount64();
                uint32_t lastInput = lii.dwTime;
                
                // Handle 32-bit wraparound
                if (now - lastInput > (1ULL << 32)) {
                    idleMs = now - (0xFFFFFFFFULL - lastInput + 1ULL);
                } else {
                    idleMs = now - lastInput;
                }
                isIdleInfoValid = true;
            }

            // [INTEGRATION] Idle Core Parking Trigger
            // Park if idle > 30s AND not in Game Mode
            if (isIdleInfoValid) 
            {
                static bool lastIdleState = false;
                // Hardcoded 30s threshold for core parking (separate from revert policy)
                bool currentIdleState = (idleMs >= 30000) && (g_lastMode.load() != 1);
                
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

                // Trigger if NOT already in browser mode (2) and idle time exceeded
                if (currentMode == 1 && idleMs >= thresholdMs)
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
                if (g_etwSession.load() == 0)
                {
                    // Prevent infinite thread spawning loop
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
                    else if (retryCount >= 3 && (now - lastRestartAttempt > 3600000))
                    {
                        retryCount = 0; // Reset after 1 hour
                    }
                }
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
    
    // [CACHE] Atomic destruction on shutdown
    SessionSmartCache* oldCache = g_sessionCache.exchange(nullptr, std::memory_order_acquire);
    if (oldCache) delete oldCache;
    
    StopEtwSession();
    
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
