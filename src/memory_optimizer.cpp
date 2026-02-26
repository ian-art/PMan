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

#include "memory_optimizer.h"
#include "globals.h"
#include "logger.h"
#include "responsiveness_provider.h"
#include "utils.h"
#include <psapi.h>
#include <pdhmsg.h>
#include <tlhelp32.h> // Required for Snapshot
#include <iostream>
#include <algorithm>
#include <vector> // Required for std::vector

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

// NOTE: NTSTATUS and SYSTEM_INFORMATION_CLASS are defined in <winternl.h> (included via types.h)
// NOTE: SYSTEM_MEMORY_LIST_COMMAND is defined in "types.h"

// Function Pointer Definition for ntdll.dll export
typedef NTSTATUS(WINAPI* PNT_SET_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

MemoryOptimizer::MemoryOptimizer() 
    : m_running(false), m_pdhQuery(nullptr), m_pdhCounter(nullptr) {
}

MemoryOptimizer::~MemoryOptimizer() {
    Shutdown();
}

void MemoryOptimizer::Initialize() {
    EnablePrivileges();
    InitializePageFaultCounter();
    m_running = true;
    Log("[MEMOPT] Memory Optimizer Initialized (Working Set Trim Only)");
}

void MemoryOptimizer::Shutdown() {
    m_running = false;

    std::vector<DWORD> pidsToUnlock;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        pidsToUnlock = m_hardenedPids;
        m_hardenedPids.clear();
    }

    // [CLEANUP] Release all memory locks ("Return the Keys")
    if (!pidsToUnlock.empty()) {
        for (DWORD pid : pidsToUnlock) {
            HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                // [SAFETY] Do NOT use -1,-1 (EmptyWorkingSet). That causes lag.
                // Instead, get current limits and re-apply them with Flags=0 (Unlocked).
                SIZE_T min, max;
                DWORD flags;
                if (GetProcessWorkingSetSizeEx(hProc, &min, &max, &flags)) {
                    // Re-apply same sizes, but REMOVE the "Hard" flags by passing 0.
                    SetProcessWorkingSetSizeEx(hProc, min, max, 0);
                }
                CloseHandle(hProc);
            }
        }
        Log("[MEMOPT] Released memory locks on shutdown (Seamless Handover).");
    }

    if (m_pdhCounter) {
        PdhRemoveCounter(m_pdhCounter);
        m_pdhCounter = nullptr;
    }
    if (m_pdhQuery) {
        PdhCloseQuery(m_pdhQuery);
        m_pdhQuery = nullptr;
    }
}

bool MemoryOptimizer::IsShieldActive() {
    std::lock_guard<std::mutex> lock(m_mtx);
    return !m_hardenedPids.empty();
}

void MemoryOptimizer::HardenProcess(DWORD pid) {
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        // [TRACK] Remember this PID so we can unlock it later
        bool found = false;
        for (DWORD existing : m_hardenedPids) {
            if (existing == pid) { found = true; break; }
        }
        if (!found) m_hardenedPids.push_back(pid);
    }

    HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProc, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        // We set the Minimum Working Set to the current usage, and Enable the "Hard Limit".
        // This tells the OS: "Under no circumstances should you trim this process below this amount."
        // We leave Maximum as -1 (Unlimited).
        SIZE_T current = pmc.WorkingSetSize;
        
        // Safety: Only harden if the game has loaded significant assets (>200MB)
        if (current > 200 * 1024 * 1024) {
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                // Working set modification execution moved strictly to SandboxExecutor TryExecute 
                // as part of enforcing the Sandbox Barrier.
                // The intent is intercepted by the Sandbox.
            }
        }
    }
    CloseHandle(hProc);
}

void MemoryOptimizer::EnablePrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
        return;

    // We need SeProfileSingleProcessPrivilege to purge the Standby List
    // We need SeIncreaseQuotaPrivilege to Hard-Lock (Pin) game memory
    const wchar_t* privileges[] = { L"SeDebugPrivilege", L"SeProfileSingleProcessPrivilege", L"SeIncreaseQuotaPrivilege" };
    
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    for (const auto* priv : privileges) {
        if (LookupPrivilegeValueW(NULL, priv, &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    CloseHandle(hToken);
}

void MemoryOptimizer::InitializePageFaultCounter() {
    if (m_pdhQuery) return;
    if (PdhOpenQueryW(nullptr, 0, &m_pdhQuery) != ERROR_SUCCESS) return;
    
    // Attempt to add the Page Faults/sec counter
    // Note: This path works on English systems. For full localization support, 
    // PdhLookupPerfNameByIndex should ideally be used in the future.
    // [FIX] Use PdhAddEnglishCounterW to support non-English Windows locales
    if (PdhAddEnglishCounterW(m_pdhQuery, L"\\Memory\\Page Faults/sec", 0, &m_pdhCounter) != ERROR_SUCCESS) {
        Log("[MEMOPT] Warning: Failed to add Page Fault counter. Monitoring might be limited.");
    }
    PdhCollectQueryData(m_pdhQuery);
}

MemoryOptimizer::MemorySnapshot MemoryOptimizer::CollectSnapshot() {
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    DWORD hardFaultsPerSec = 0;
    if (m_pdhQuery && m_pdhCounter) {
        PDH_FMT_COUNTERVALUE value{};
        PdhCollectQueryData(m_pdhQuery);
        if (ERROR_SUCCESS == PdhGetFormattedCounterValue(m_pdhCounter, PDH_FMT_DOUBLE, nullptr, &value)) {
            hardFaultsPerSec = static_cast<DWORD>(value.doubleValue);
        }
    }

    return { 0, mem.dwMemoryLoad, hardFaultsPerSec };
}

void MemoryOptimizer::FlushStandbyList() {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return;

    auto NtSetSystemInformation = (PNT_SET_SYSTEM_INFORMATION)GetProcAddress(hNtDll, "NtSetSystemInformation");
    if (!NtSetSystemInformation) return;

    // Command 4 is MemoryPurgeStandbyList
    SYSTEM_MEMORY_LIST_COMMAND command = MemoryPurgeStandbyList;
    
    // SystemMemoryListInformation (80) is defined in types.h via macro/cast
    NTSTATUS status = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));

    if (status >= 0) {
        Log("[MEMOPT] System Standby List Purged (Cached memory freed)");
    }
}

bool MemoryOptimizer::IsTargetProcess(const std::wstring& procName) {
    std::shared_lock<std::shared_mutex> lock(g_setMtx);
    
    // Check Games
    if (g_games.find(procName) != g_games.end()) return true;
    
    // Check Browsers (Optional: Browsers are also heavy memory users)
    if (g_browsers.find(procName) != g_browsers.end()) return true;

    // Check Custom Launchers
    if (g_customLaunchers.find(procName) != g_customLaunchers.end()) return true;

    return false;
}

DWORD MemoryOptimizer::ProposeTrimTarget(DWORD foregroundPid) {
    // Resolve foreground process name to prevent cannibalizing child/related processes
    std::wstring fgName;
    {
        HANDLE hFgRaw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, foregroundPid);
        if (hFgRaw) {
            UniqueHandle hFgProc(hFgRaw);
            wchar_t fBuf[MAX_PATH];
            DWORD fLen = MAX_PATH;
            if (QueryFullProcessImageNameW(hFgRaw, 0, fBuf, &fLen)) {
                fgName = std::filesystem::path(fBuf).filename().wstring();
                std::transform(fgName.begin(), fgName.end(), fgName.begin(), ::towlower);
            }
        }
    }

    // [FIX] C6262: Use heap allocation instead of large stack array
    std::vector<DWORD> pids(4096);
    DWORD needed{};
    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &needed)) return 0;

    DWORD myPid = GetCurrentProcessId();
    size_t count = needed / sizeof(DWORD);
    auto now = std::chrono::steady_clock::now();

    DWORD worstPid = 0;
    SIZE_T worstWorkingSet = 0;

    for (size_t i = 0; i < count; i++) {
        DWORD pid = pids[i];

        // [SAFETY] Skip kernel PIDs, self, and the protected foreground process
        if (pid == 0 || pid == 4 || pid == myPid || pid == foregroundPid) continue;

        // Check internal cooldown (read-only — sensor does not write to tracker)
        if (m_processTracker.count(pid)) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_processTracker[pid].lastTrimTime).count();
            if (elapsed < PROCESS_COOLDOWN_SEC) continue;
        }

        // [SENSOR] Open with read-only flags — no mutation flags permitted
        HANDLE hProcRaw = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, pid
        );

        if (!hProcRaw) {
            // Process gone or access denied; reset tracker state for this PID
            if (m_processTracker.count(pid)) m_processTracker.erase(pid);
            continue;
        }
        UniqueHandle hProc(hProcRaw);

        // [RACE FIX] Verify PID Identity: skip brand-new processes (< 2 seconds old)
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcRaw, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            ULARGE_INTEGER ulCreate;
            ulCreate.LowPart = ftCreate.dwLowDateTime;
            ulCreate.HighPart = ftCreate.dwHighDateTime;

            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);
            ULARGE_INTEGER ulNow;
            ulNow.LowPart = ftNow.dwLowDateTime;
            ulNow.HighPart = ftNow.dwHighDateTime;

            // 10,000,000 ticks per second. 2 seconds = 20,000,000
            if (ulNow.QuadPart > ulCreate.QuadPart && (ulNow.QuadPart - ulCreate.QuadPart) < 20000000) {
                continue;
            }
        }

        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcRaw, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            if (pmc.WorkingSetSize > MIN_MEM_TO_TRIM) {
                wchar_t buf[MAX_PATH];
                DWORD len = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcRaw, 0, buf, &len)) {
                    std::filesystem::path p(buf);
                    std::wstring name = p.filename().wstring();
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

                    // Critical Safety Check: never trim AV or system processes
                    if (IsSystemCriticalProcess(name)) continue;

                    // [FIX] Safety: Don't target child processes of the active application
                    if (!fgName.empty() && name == fgName) continue;

                    {
                        std::shared_lock<std::shared_mutex> lock(g_setMtx);
                        if (g_ignoredProcesses.find(name) != g_ignoredProcesses.end()) continue;
                    }
                }

                // [SENSOR] Track worst offender by largest working set; do not execute any trim
                // Track worst offender by largest working set
                if (pmc.WorkingSetSize > worstWorkingSet) {
                    worstWorkingSet = pmc.WorkingSetSize;
                    worstPid = pid;
                }
            }
        }
    }

    return worstPid;
}

DWORD MemoryOptimizer::ProposeHardenTarget(DWORD foregroundPid) {
    if (foregroundPid == 0) return 0;

    HANDLE hProcRaw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, foregroundPid);
    if (!hProcRaw) return 0;
    UniqueHandle hProc(hProcRaw);

    wchar_t buf[MAX_PATH];
    DWORD len = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcRaw, 0, buf, &len)) return 0;

    std::wstring name = std::filesystem::path(buf).filename().wstring();
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);

    {
        std::shared_lock<std::shared_mutex> lock(g_setMtx);
        if (g_games.find(name) == g_games.end()) return 0;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (!GetProcessMemoryInfo(hProcRaw, &pmc, sizeof(pmc))) return 0;

    if (pmc.WorkingSetSize > 200 * 1024 * 1024) {
        return foregroundPid;
    }

    return 0;
}
