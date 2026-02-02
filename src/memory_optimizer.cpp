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
    if (m_pdhCounter) {
        PdhRemoveCounter(m_pdhCounter);
        m_pdhCounter = nullptr;
    }
    if (m_pdhQuery) {
        PdhCloseQuery(m_pdhQuery);
        m_pdhQuery = nullptr;
    }
}

void MemoryOptimizer::EnablePrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
        return;

    // We need SeProfileSingleProcessPrivilege to purge the Standby List
    const wchar_t* privileges[] = { L"SeDebugPrivilege", L"SeProfileSingleProcessPrivilege" };
    
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
    if (PdhAddCounterW(m_pdhQuery, L"\\Memory\\Page Faults/sec", 0, &m_pdhCounter) != ERROR_SUCCESS) {
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

void MemoryOptimizer::SmartMitigate(DWORD foregroundPid) {
    // Rate limit to once per minute
    static uint64_t lastMitigation = 0;
    uint64_t nowTick = GetTickCount64();
    if (nowTick - lastMitigation < 60000) return;
    lastMitigation = nowTick;

    // Offload to background thread
    std::thread([this, foregroundPid]() {
        // Resolve foreground process name to prevent cannibalizing child processes (e.g. Chrome Renderers)
        std::wstring fgName;
        HANDLE hFgProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, foregroundPid);
    if (hFgProc) {
        wchar_t fBuf[MAX_PATH];
        DWORD fLen = MAX_PATH;
        if (QueryFullProcessImageNameW(hFgProc, 0, fBuf, &fLen)) {
            fgName = std::filesystem::path(fBuf).filename().wstring();
            std::transform(fgName.begin(), fgName.end(), fgName.begin(), ::towlower);
        }
        CloseHandle(hFgProc);
    }

    DWORD needed{};
    // [FIX] C6262: Use heap allocation instead of large stack array
    std::vector<DWORD> pids(4096);
    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &needed)) return;

    DWORD myPid = GetCurrentProcessId();
    size_t count = needed / sizeof(DWORD);
    int trimmedCount = 0;
    SIZE_T totalFreedBytes = 0;
    auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < count; i++) {
        DWORD pid = pids[i];
        if (pid == 0 || pid == myPid || pid == foregroundPid) continue;

		// [SAFETY] Do not rely on PID heuristics (pid < 1000). 
        // Only skip strictly known kernel PIDs here. 
        // Real system processes are filtered via IsSystemCriticalProcess() later to prevent BSODs.
        if (pid == 0 || pid == 4) continue;

        // Check internal cooldown
        if (m_processTracker.count(pid)) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_processTracker[pid].lastTrimTime).count();
            if (elapsed < PROCESS_COOLDOWN_SEC) continue; 
        }

        // Proceed to open handle. We check exclusion list name later to save perf on invalid handles.
        HANDLE hProc = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 
            FALSE, pid
        );

        if (!hProc) {
            // Process gone or access denied. 
            // Do NOT update lastTrimTime here; if the PID is reused later, we want to treat it as new.
            // m_processTracker[pid].lastTrimTime = now; <--- REMOVED
            // Instead, remove it from tracker to reset state
            if (m_processTracker.count(pid)) m_processTracker.erase(pid);
            continue;
        }

        // [RACE FIX] Verify PID Identity: Ensure this is not a reused PID
        // If the process is brand new (< 2 seconds old), skip trimming to allow initialization
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
             ULARGE_INTEGER ulCreate;
             ulCreate.LowPart = ftCreate.dwLowDateTime;
             ulCreate.HighPart = ftCreate.dwHighDateTime;
             
             // Current system time as FILETIME
             FILETIME ftNow;
             GetSystemTimeAsFileTime(&ftNow);
             ULARGE_INTEGER ulNow;
             ulNow.LowPart = ftNow.dwLowDateTime;
             ulNow.HighPart = ftNow.dwHighDateTime;

             // 10,000,000 ticks per second. 2 seconds = 20,000,000
             if (ulNow.QuadPart > ulCreate.QuadPart && (ulNow.QuadPart - ulCreate.QuadPart) < 20000000) {
                 CloseHandle(hProc);
                 continue; 
             }
        }

        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProc, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            
            if (pmc.WorkingSetSize > MIN_MEM_TO_TRIM) {
                
                // Check Exclusion List
                wchar_t buf[MAX_PATH];
                DWORD len = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
                    std::filesystem::path p(buf);
                    std::wstring name = p.filename().wstring();
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                    
                    // Critical Safety Check (Defender Safe)
                    // Explicitly prevent trimming AV or System processes
                    if (IsSystemCriticalProcess(name)) {
                        CloseHandle(hProc);
                        continue;
                    }

                    // [FIX] Safety: Don't trim child processes of the active application
                    if (!fgName.empty() && name == fgName) {
                        CloseHandle(hProc);
                        continue;
                    }

                    std::shared_lock<std::shared_mutex> lock(g_setMtx);
                    if (g_ignoredProcesses.find(name) != g_ignoredProcesses.end()) {
                        CloseHandle(hProc);
                        continue;
                    }
                }

                // [FIX] Use "Soft Trim" via Quota Limits.
                // Flags = 0 (QUOTA_LIMITS_HARDWS_MIN_DISABLE) allows the OS to reclaim 
                // unused pages without forcing a full flush to disk (Hard Fault Storm).
                // Min=4KB, Max=256MB (Soft limits, expandable).
                if (SetProcessWorkingSetSizeEx(hProc, 4096, 256 * 1024 * 1024, 0)) {
                    trimmedCount++;
                    // Estimate freed (OS decides actual amount, but we log the potential)
                    totalFreedBytes += (pmc.WorkingSetSize > (4 * 1024 * 1024) ? pmc.WorkingSetSize - (4 * 1024 * 1024) : 0);
                }
                
                m_processTracker[pid].lastTrimTime = now;
            }
        }
        CloseHandle(hProc);
    }

    if (trimmedCount > 0) {
        Log("[MEMOPT] High Pressure Mitigation: Trimmed " + std::to_string(trimmedCount) + 
            " processes (" + std::to_string(totalFreedBytes / 1024 / 1024) + " MB)");

        // Intelligent Standby Purge
        auto timeSincePurge = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_lastPurgeTime).count();

        // Only purge if we freed significant RAM (>100MB) AND cooldown expired
        if (timeSincePurge > PURGE_COOLDOWN_SEC && totalFreedBytes > (100 * 1024 * 1024)) {
            // [FIX] Disable Standby List Purge.
            // Purging the Standby List deletes file cache (icons, DLLs), causing 
            // immediate micro-stutters when the user opens Start Menu or switches apps.
            // Modern Windows (10/11) manages Standby memory correctly; empty RAM is wasted RAM.
            // FlushStandbyList(); <--- COMMENTED OUT TO FIX LAG
            Log("[MEMOPT] Trim complete. Standby List Purge skipped to preserve responsiveness.");
            m_lastPurgeTime = now;
        }
    }
    // End of background thread
    }).detach();
}

void MemoryOptimizer::RunThread() {
    Log("[MEMOPT] Background Monitor Thread Started");

    while (m_running) {
        // Cleanup dead processes every hour to prevent map bloat
        static uint64_t lastCleanup = 0;
        uint64_t nowTick = GetTickCount64();
        if (nowTick - lastCleanup > 3600000) {
            for (auto it = m_processTracker.begin(); it != m_processTracker.end(); ) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, it->first);
                bool dead = (!hProc);
                if (hProc) {
                    DWORD exitCode = 0;
                    if (!GetExitCodeProcess(hProc, &exitCode) || exitCode != STILL_ACTIVE) dead = true;
                    CloseHandle(hProc);
                }
                if (dead) it = m_processTracker.erase(it); else ++it;
            }
            lastCleanup = nowTick;
        }

        // 1. Check Pause State
        if (g_userPaused.load() || g_isSuspended.load()) {
            Sleep(1000);
            continue;
        }

        // 2. Browser Check: Abort logic if ANY browser is running (User Constraint)
        bool browserRunning = false;
        {
            // Scope for snapshot handles
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        std::shared_lock<std::shared_mutex> lock(g_setMtx);
                        if (g_browsers.find(pe.szExeFile) != g_browsers.end()) {
                            browserRunning = true;
                            break;
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }

        if (browserRunning) {
            Sleep(2000); // Check again later
            continue; 
        }

        // 3. Identify Foreground
        HWND hFg = GetForegroundWindow();
        DWORD fgPid = 0;
        GetWindowThreadProcessId(hFg, &fgPid);
        
        std::wstring fgName = L"";
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, fgPid);
        if (hProc) {
            wchar_t buf[MAX_PATH];
            DWORD len = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
                fgName = std::filesystem::path(buf).filename().wstring();
            }
            CloseHandle(hProc);
        }
        std::transform(fgName.begin(), fgName.end(), fgName.begin(), ::towlower);

        // 4. Check if target active (Game)
        if (IsTargetProcess(fgName)) {
            // SRAM Policy Integration
            // Rule: If SLIGHT_PRESSURE (or worse), pause background trimming.
            // Memory trimming is I/O and Lock intensive; we must back off early.
            if (GetSystemResponsiveness() >= LagState::SLIGHT_PRESSURE) {
                Sleep(2000); // Wait for system to settle
                continue;
            }

            // Monitor Logic
            MemorySnapshot snap = CollectSnapshot();
            
            // Trigger if RAM load > 85% OR Page Faults > 2000/sec
            bool pressureHigh = (snap.memoryLoadPercent > 80 || snap.hardFaultsPerSec > HARD_FAULT_THRESHOLD);
            
            if (pressureHigh) {
                // Run Mitigation
                SmartMitigate(fgPid);
                
                // Cooldown to prevent spamming trims
                for (int i=0; i<5 && m_running; i++) Sleep(1000); 
            }
        } else {
            // Passive cleanup for map to prevent memory leaks
            if (m_processTracker.size() > 1000) m_processTracker.clear();
        }

        Sleep(1000);
    }
}

void MemoryOptimizer::PerformSmartTrim(const std::vector<DWORD>& targets, TrimIntensity intensity) {
    std::lock_guard<std::mutex> lock(m_mtx);

    // 1. Global Action: Flush Standby List (Hard Mode Only)
    // Phase 13.2: "Flush System Standby List (Global benefit)"
    if (intensity == TrimIntensity::Hard) {
        FlushStandbyList();
    }

    // 2. Targeted Action
    for (DWORD pid : targets) {
        // Skip own process and critical system processes
        if (pid == GetCurrentProcessId() || pid == 0 || pid == 4) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid);
        if (!hProcess) continue;
        UniqueHandle uhProcess(hProcess);

        // Phase 13.2: "DO NOT touch the Game/Foreground App"
        // (This filtering is expected to be done by the Executor's Targeting System,
        // but we double-check implementation constraints if needed. 
        // For now, we trust the 'targets' vector passed by Executor).

        SIZE_T minWS, maxWS;
        if (GetProcessWorkingSetSize(hProcess, &minWS, &maxWS)) {
            bool shouldTrim = true;

            // Phase 13: "Gentle Trim" logic
            if (intensity == TrimIntensity::Gentle) {
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    if (pmc.WorkingSetSize < 100 * 1024 * 1024) { // < 100MB
                        shouldTrim = false;
                    }
                }
            }

            if (shouldTrim) {
                // EmptyWorkingSet is achieved by passing -1, -1
                SetProcessWorkingSetSize(hProcess, (SIZE_T)-1, (SIZE_T)-1);
            }
        }
    }
}
