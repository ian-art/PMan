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

#include "etw_monitor.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "performance.h"
#include "idle_affinity.h"
#include "events.h" // For PostIocp
#include "executor.h"
#include <tdh.h>
#include <evntrace.h> // Required for EVENT_RECORD types

// Helper to clean up process state (Copied from events.cpp logic)
static void CleanupProcessState(DWORD pid) {
    { std::lock_guard lock(g_workingSetMtx); g_originalWorkingSets.erase(pid); }
    { std::lock_guard lock(g_trimTimeMtx); g_lastTrimTimes.erase(pid); }
    { std::lock_guard lock(g_dpcStateMtx); g_processesWithBoostDisabled.erase(pid); }
}
#include <evntrace.h>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_set>
#include <thread>
#include <algorithm>
#include <objbase.h> // For CoInitialize

// Dependencies
#pragma comment(lib, "Tdh.lib")

// Internal State
static std::atomic<TRACEHANDLE> g_etwSessionLocal{0};
static std::mutex g_etwSessionMtxLocal;
static std::atomic<uint64_t> g_lastEtwHeartbeatLocal{0};

// [CIRCUIT BREAKER] Track critical system PIDs
static std::unordered_set<DWORD> g_criticalPids;
static std::mutex g_criticalPidsMtx;

// GUIDs
static const GUID KernelProcessGuid = { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
static const GUID DPCGuid = { 0x13976d09, 0x032d, 0x4fd7, { 0x81, 0x0a, 0x44, 0x40, 0x2c, 0x10, 0xe2, 0xc1 } };
static const GUID ISRGuid = { 0x99f948be, 0xb355, 0x4fc8, { 0x88, 0x7c, 0x7f, 0xf4, 0x67, 0x9c, 0x88, 0x4d } };

// Helper RAII
struct TraceSessionGuard {
    TRACEHANDLE handle;
    const wchar_t* name;
    TraceSessionGuard(TRACEHANDLE h, const wchar_t* n) : handle(h), name(n) {}
    ~TraceSessionGuard() {
        if (handle) {
            size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + ((wcslen(name) + 1) * sizeof(wchar_t));
            std::vector<BYTE> buffer(propsSize);
            ZeroMemory(buffer.data(), buffer.size());
            PEVENT_TRACE_PROPERTIES props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
            props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(handle, name, props, EVENT_TRACE_CONTROL_STOP);
        }
    }
};

void EtwMonitor::Stop() {
    std::lock_guard lock(g_etwSessionMtxLocal);
    TRACEHANDLE session = g_etwSessionLocal.exchange(0);
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

bool EtwMonitor::IsSessionActive() {
    return g_etwSessionLocal.load() != 0;
}

uint64_t EtwMonitor::GetLastHeartbeat() {
    return g_lastEtwHeartbeatLocal.load(std::memory_order_relaxed);
}

void EtwMonitor::Run() {
    g_threadCount++;
    g_lastEtwHeartbeatLocal.store(GetTickCount64(), std::memory_order_relaxed);

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

    if (status == ERROR_ALREADY_EXISTS) {
        Log("[ETW] Session already exists. Attempting recovery...");
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        Sleep(100);
        status = StartTraceW(&hSession, SESSION_NAME, props);
    }

    if (status == ERROR_SUCCESS) {
        if (hSession != 0 && hSession != INVALID_PROCESSTRACE_HANDLE) {
            std::lock_guard lock(g_etwSessionMtxLocal);
            g_etwSessionLocal.store(hSession);
        }
    }   

    if (status != ERROR_SUCCESS) {
        Log("ETW: StartTrace failed: " + std::to_string(status));
        CoUninitialize();
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    status = EnableTraceEx2(hSession, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0x10, 0, 0, nullptr);

    // Microsoft-Windows-DxgKrnl
    static const GUID DxgKrnlGuid = { 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };
    EnableTraceEx2(hSession, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr);

    // DirectX 9
    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    EnableTraceEx2(hSession, &D3D9Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr);

    // DirectX 10
    static const GUID D3D10Guid = { 0x9B7E4C8F, 0x342C, 0x4106, { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
    EnableTraceEx2(hSession, &D3D10Guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0x1, 0, 0, nullptr);

#if defined(_M_AMD64) || defined(_M_IX86)
    // DPC/ISR Disabled by default for perf
    status = ERROR_SUCCESS;
#else
    status = ERROR_SUCCESS;
#endif

    if (status != ERROR_SUCCESS) {
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

    TraceSessionGuard sessionGuard(hSession, SESSION_NAME);

    TRACEHANDLE hTrace = OpenTraceW(&t);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        Log("ETW: OpenTrace failed: " + std::to_string(GetLastError()));
        CoUninitialize();
        g_threadCount--;
        g_shutdownCv.notify_one();
        return;
    }

    ULONG processStatus = ProcessTrace(&hTrace, 1, nullptr, nullptr);
    
    if (processStatus != ERROR_SUCCESS && processStatus != ERROR_CANCELLED) {
        Log("[ETW] ProcessTrace returned: " + std::to_string(processStatus));
    }

    CloseTrace(hTrace);
    g_etwSessionLocal.store(0);
    CoUninitialize();
    g_threadCount--;
    g_shutdownCv.notify_one();
}

void EtwMonitor::CheckHealthAndRecover() {
    if (!g_running) return;

    // Prevent False Positive during Sleep/Resume
    if (g_isSuspended.load()) {
        g_lastEtwHeartbeatLocal.store(GetTickCount64(), std::memory_order_relaxed);
        return;
    }

    static std::atomic<int> retryCount{0};
    static std::atomic<uint64_t> lastRestartAttempt{0};
    
    uint64_t now = GetTickCount64();
    bool needsRestart = !IsSessionActive();

    // Silence Detection
    if (!needsRestart) {
        uint64_t lastBeat = g_lastEtwHeartbeatLocal.load(std::memory_order_relaxed);
        if (now - lastBeat > 60000) {
            Log("[HEALTH] ETW session silent for >60s. Forcing restart...");
            Stop();
            needsRestart = true;
        } else {
            if (retryCount > 0) retryCount.store(0);
        }
    }

    if (needsRestart) {
        if (retryCount < 3 && (now - lastRestartAttempt > 5000)) {
            Log("[HEALTH] ETW Session is not running. Restarting (Attempt " + 
                std::to_string(retryCount + 1) + "/3)...");
            lastRestartAttempt = now;
            retryCount++;

            std::thread restartThread([]() {
                Run(); 
            });
            restartThread.detach();
        } else if (retryCount >= 3 && (now - lastRestartAttempt > 3600000)) {
            retryCount = 0; // Reset after 1 hour
        }
    }
}

void WINAPI EtwMonitor::DpcIsrCallback(EVENT_RECORD* rec) {
    static constexpr size_t DPC_RING_SIZE = 128;
    static uint64_t dpcRingBuffer[DPC_RING_SIZE] = {0};
    static size_t dpcRingHead = 0;
    static size_t dpcRingCount = 0;
    
    if (!rec) return;

    DWORD bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    
    if (bufferSize == 0 || bufferSize > 4096) return;
    BYTE buffer[4096]; 
    
    TRACE_EVENT_INFO* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer);
    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) 
        return;

    if (rec->EventHeader.EventDescriptor.Id == 2) { // DPCExec
        ULONGLONG duration = 0;
        for (DWORD i = 0; i < info->PropertyCount; i++) {
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);
            
            if (!propName || propName[0] != L'D') continue;
            if (wcscmp(propName, L"Duration") != 0) continue;

            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
            desc.ArrayIndex = ULONG_MAX;
            desc.Reserved = 0;
            DWORD sz = sizeof(duration);
            
            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, 
                             reinterpret_cast<BYTE*>(&duration)) == ERROR_SUCCESS) {
                
                uint64_t latencyUs = duration / 10;
                
                dpcRingBuffer[dpcRingHead] = latencyUs;
                dpcRingHead = (dpcRingHead + 1) % DPC_RING_SIZE;
                if (dpcRingCount < DPC_RING_SIZE) dpcRingCount++;
                
                if (dpcRingHead == 0 && dpcRingCount == DPC_RING_SIZE) {
                    uint64_t snapshot[DPC_RING_SIZE];
                    memcpy(snapshot, dpcRingBuffer, sizeof(snapshot));
                    size_t idx = (DPC_RING_SIZE * 95) / 100;
                    std::nth_element(snapshot, snapshot + idx, snapshot + DPC_RING_SIZE);
                    PManContext::Get().telem.lastDpcLatency.store(static_cast<double>(snapshot[idx]), std::memory_order_relaxed);
                }
            }
            break;
        }
    }
}

void WINAPI EtwMonitor::EtwCallback(EVENT_RECORD* rec) {
    if (!rec || !g_running) return;

    g_lastEtwHeartbeatLocal.store(GetTickCount64(), std::memory_order_relaxed);

    static const GUID DxgKrnlGuid = { 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, DxgKrnlGuid)) {
        DWORD pid = rec->EventHeader.ProcessId;
        uint64_t timestamp = rec->EventHeader.TimeStamp.QuadPart;
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;

        bool isPresentEvent = (eventId == 46 || eventId == 60 || eventId == 68 || eventId == 184 || eventId == 252);
        if (isPresentEvent) {
             g_perfGuardian.OnPresentEvent(pid, timestamp);
        }
        return;
    }

    static const GUID D3D9Guid = { 0x783ACA0A, 0x790E, 0x4d7f, { 0x8A, 0x51, 0xC4, 0x15, 0x1E, 0x9F, 0x6F, 0xD3 } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, D3D9Guid)) {
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;
        if (eventId >= 1 && eventId <= 3) {
            g_perfGuardian.OnPresentEvent(rec->EventHeader.ProcessId, rec->EventHeader.TimeStamp.QuadPart);
        }
        return;
    }

    static const GUID D3D10Guid = { 0x9B7E4C8F, 0x342C, 0x4106, { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
    if (IsEqualGUID(rec->EventHeader.ProviderId, D3D10Guid)) {
        USHORT eventId = rec->EventHeader.EventDescriptor.Id;
        if (eventId == 8 || eventId == 10) {
            g_perfGuardian.OnPresentEvent(rec->EventHeader.ProcessId, rec->EventHeader.TimeStamp.QuadPart);
        }
        return;
    }

    if (IsEqualGUID(rec->EventHeader.ProviderId, DPCGuid) || IsEqualGUID(rec->EventHeader.ProviderId, ISRGuid)) {
        DpcIsrCallback(rec);
        return;
    }

    BYTE opcode = rec->EventHeader.EventDescriptor.Opcode;
    if (opcode != 1 && opcode != 2) return;

    DWORD bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    if (bufferSize == 0) return;

    std::vector<BYTE> buffer(bufferSize);
    TRACE_EVENT_INFO* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());

    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) == ERROR_SUCCESS) {
        DWORD pid = 0;
        DWORD parentPid = 0;

        for (DWORD i = 0; i < info->PropertyCount; i++) {
            wchar_t* propName = reinterpret_cast<wchar_t*>(
                reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset);

            if (propName) {
                if (wcscmp(propName, L"ProcessID") == 0) {
                    PROPERTY_DATA_DESCRIPTOR desc = { reinterpret_cast<ULONGLONG>(propName), ULONG_MAX, 0 };
                    DWORD sz = sizeof(pid);
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, reinterpret_cast<BYTE*>(&pid));
                }
                else if (opcode == 1 && wcscmp(propName, L"ParentProcessID") == 0) {
                    PROPERTY_DATA_DESCRIPTOR desc = { reinterpret_cast<ULONGLONG>(propName), ULONG_MAX, 0 };
                    DWORD sz = sizeof(parentPid);
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, sz, reinterpret_cast<BYTE*>(&parentPid));
                }
            }
        }

        if (pid != 0 && g_running) {
            if (opcode == 1) { // Start
                static const std::vector<std::wstring> CRITICAL_NAMES = {
                    L"csrss.exe", L"lsass.exe", L"services.exe", 
                    L"wininit.exe", L"winlogon.exe", L"dwm.exe",
                    L"StartMenuExperienceHost.exe", L"ShellExperienceHost.exe", 
                    L"SearchApp.exe", L"TextInputHost.exe", L"notepad.exe"
                };

                bool isCritical = false;
                std::wstring imgName = GetProcessNameFromPid(pid); 
                if (!imgName.empty()) {
                    for (const auto& crit : CRITICAL_NAMES) {
                        if (ContainsIgnoreCase(imgName, crit)) {
                            {
                                std::lock_guard lock(g_criticalPidsMtx);
                                g_criticalPids.insert(pid);
                            }
                            isCritical = true;
                            break;
                        }
                    }
                }

                if (g_idleAffinityMgr.IsIdle()) {
                    g_idleAffinityMgr.OnProcessStart(pid);
                }

                ProcessIdentity identity;
                if (GetProcessIdentity(pid, identity)) {
                    std::unique_lock lg(g_hierarchyMtx);
                    ProcessNode node;
                    node.identity = identity;
                    node.inheritedMode = 0;

                    ProcessIdentity parentIdentity;
                    if (parentPid != 0 && GetProcessIdentity(parentPid, parentIdentity)) {
                        node.parent = parentIdentity;
                        auto it = g_processHierarchy.find(parentIdentity);

                        if (it != g_processHierarchy.end()) {
                            it->second.children.push_back(identity);
                            if (it->second.inheritedMode == 1 || g_inheritedGamePids.count(parentPid)) {
                                node.inheritedMode = 1;
                                g_inheritedGamePids[pid] = identity;
                                Log("[HIERARCHY] Child " + std::to_string(pid) + " inherits GAME mode from " + std::to_string(parentPid));
                            }
                        }
                    }
                    g_processHierarchy[identity] = node;
                }

                if (!isCritical) {
                    PostIocp(JobType::Policy, pid);
                }
            }
            else if (opcode == 2) { // End
                {
                    std::lock_guard lock(g_criticalPidsMtx);
                    if (g_criticalPids.erase(pid)) {
                        Log("[CIRCUIT BREAKER] CRITICAL SYSTEM PROCESS EXIT DETECTED (PID " + std::to_string(pid) + ")");
                        Log("[CIRCUIT BREAKER] TRIGGERING EMERGENCY REVERT ALL...");
                        Executor::Get().EmergencyRevertAll();
                    }
                }
                CleanupProcessState(pid);
                std::unique_lock lg(g_hierarchyMtx);
                g_inheritedGamePids.erase(pid);
            }
        }
    }
}
