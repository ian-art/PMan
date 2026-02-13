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

// [CRITICAL] Version Macros MUST be defined before ANY headers
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0601 // Windows 7+

#ifdef WINVER
#undef WINVER
#endif
#define WINVER 0x0601

// [CRITICAL] Windows headers MUST be included before Project headers
// This ensures 'werapi.h' (Wait Chain Traversal) is loaded with the correct version.
#include <windows.h>
#include <wct.h> // [FIX] Correct header for Wait Chain Traversal
#include <tlhelp32.h>    // Thread Snapshot
#pragma comment(lib, "Advapi32.lib") // Linker dependency for WCT

// Standard C++ Headers
#include <thread>
#include <chrono>
#include <vector>

// Project Headers
#include "investigator.h"
#include "context.h"
#include "logger.h"
#include "sysinfo.h" 

// [RAII] WCT Session Wrapper
// Encapsulates the raw HWCT handle to ensure it is always closed.
class WctSession {
public:
    WctSession() {
        // Create a synchronous WCT session
        hSession = OpenThreadWaitChainSession(0, NULL);
    }

    ~WctSession() {
        if (hSession) {
            CloseThreadWaitChainSession(hSession);
        }
    }

    HWCT Get() const { return hSession; }
    bool IsValid() const { return hSession != NULL; }

private:
    HWCT hSession;
};

// Helper for FILETIME arithmetic
static uint64_t FileTimeToInt64(const FILETIME& ft) {
    return (((uint64_t)(ft.dwHighDateTime)) << 32) | ((uint64_t)ft.dwLowDateTime);
}

Investigator::Investigator() {}

InvestigationVerdict Investigator::Diagnose(const GovernorDecision& govState) {
    InvestigationVerdict verdict = { false, DiagnosisType::None, 0.0, false };

    // 1. Analyze CPU Anomalies (Signal De-Noising)
    // If the Governor sees a spike but we are unsure (aliasing), probe it.
    if (govState.dominant == DominantPressure::Cpu) {
        DiagnosisType cpuDiag = PerformCpuMicroBurst();
        
        if (cpuDiag == DiagnosisType::FalseAlarm_Aliasing) {
            verdict.resolved = true;
            verdict.type = cpuDiag;
            verdict.confidenceBoost = 1.0; // Restore full confidence
            verdict.recommendVeto = true;  // Do not act on false alarm
            
            // Log for "The System Detective"
            // [INV] CPU Noise Detected: Snapshot=95%, BurstAvg=12%. Verdict: False Alarm.
        }
        else if (cpuDiag == DiagnosisType::TruePressure_Sustained) {
            // [REFINEMENT] Sustained pressure could be a spinlock/deadlock.
            // If the Governor has a target PID, we should probe it for deadlocks.
            if (govState.targetPid > 0) {
                DiagnosisType wctDiag = ProbeWaitChain(govState.targetPid);
                if (wctDiag == DiagnosisType::Process_Deadlocked) {
                    verdict.resolved = true;
                    verdict.type = wctDiag;
                    verdict.recommendVeto = true; // Don't boost a deadlocked app
                    verdict.confidenceBoost = 1.0;
                    return verdict;
                }
            }

            verdict.resolved = true;
            verdict.type = cpuDiag;
            verdict.confidenceBoost = 0.5; // Validated, proceed with caution
            verdict.recommendVeto = false;
        }
    }

    // 2. Analyze Disk Thrashing (Disk Safety)
    // If the Governor wants to reclaim memory (Trim), we must ensure we aren't causing hard faults.
    if (govState.allowedActions == AllowedActionClass::MemoryReclaim) {
        if (govState.targetPid > 0) {
            DiagnosisType diskDiag = ProbeDiskThrashing(govState.targetPid);
            
            if (diskDiag == DiagnosisType::IO_Thrashing) {
                verdict.resolved = true;
                verdict.type = diskDiag;
                verdict.recommendVeto = true; // VETO the trim!
                verdict.confidenceBoost = 1.0; // We are sure about this veto
                return verdict;
            }
        }
    }
    
    // 3. Analyze Process Responsiveness (Hung Window Check)
    // If we are about to Throttle a process, we must ensure it isn't actually Hung.
    // If it is Hung, we shouldn't throttle it (it needs restart/alert).
    
    // [FIX] Fallback: Check Foreground Window if no target is specified.
    // This catches scenarios where the user interface is frozen (Deadlock) but CPU usage is low.
    DWORD checkPid = govState.targetPid;
    if (checkPid == 0) {
        HWND hFg = GetForegroundWindow();
        if (hFg) GetWindowThreadProcessId(hFg, &checkPid);
    }

    if (checkPid > 0) {
        DiagnosisType hangDiag = ProbeHungWindow(checkPid);
        
        if (hangDiag == DiagnosisType::Process_Deadlocked) {
            verdict.resolved = true;
            verdict.type = hangDiag;
            verdict.recommendVeto = true; // Don't throttle a dead app
            verdict.confidenceBoost = 1.0;

            // [LOG] Explicitly log foreground hangs as they might not be the primary target
            if (govState.targetPid == 0) {
                Log("[INV] CRITICAL: Foreground Window (PID " + std::to_string(checkPid) + ") is Deadlocked/Hung.");
            }

            return verdict;
        }
    }

    return verdict;
}

DiagnosisType Investigator::PerformCpuMicroBurst() {
    // Technique: Micro-Burst Sampling.
    // Sample CPU 10 times in 50ms (5ms intervals).
    
    double accumulatedLoad = 0.0;
    int samples = 0;
    int zeroReadings = 0;
    int highReadings = 0;

    // Safety: Ensure this loop does not exceed 50ms total.
    for (int i = 0; i < MICRO_BURST_SAMPLES; ++i) {
        FILETIME idle1, kernel1, user1;
        FILETIME idle2, kernel2, user2;

        if (GetSystemTimes(&idle1, &kernel1, &user1)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(BURST_INTERVAL_MS));
            GetSystemTimes(&idle2, &kernel2, &user2);

            uint64_t idleDiff = FileTimeToInt64(idle2) - FileTimeToInt64(idle1);
            uint64_t kernelDiff = FileTimeToInt64(kernel2) - FileTimeToInt64(kernel1);
            uint64_t userDiff = FileTimeToInt64(user2) - FileTimeToInt64(user1);
            uint64_t totalSys = kernelDiff + userDiff;

            double currentLoad = 0.0;
            if (totalSys > 0) {
                currentLoad = (double)(totalSys - idleDiff) * 100.0 / totalSys;
            }

            accumulatedLoad += currentLoad;
            if (currentLoad < 5.0) zeroReadings++;
            if (currentLoad > 80.0) highReadings++;
            samples++;
        } else {
            // Fallback if GetSystemTimes fails
            std::this_thread::sleep_for(std::chrono::milliseconds(BURST_INTERVAL_MS));
        }
    }

    double average = (samples > 0) ? (accumulatedLoad / samples) : 0.0;

    // Heuristic: PWM / Aliasing Detection
    // If we have a mix of 0s and 100s, it's likely aliasing/PWM.
    if (zeroReadings > 2 && highReadings > 2) {
        return DiagnosisType::FalseAlarm_Aliasing;
    }
    
    // Heuristic: Sustained Load
    if (average > 70.0 && zeroReadings == 0) {
        return DiagnosisType::TruePressure_Sustained;
    }

    return DiagnosisType::None;
}

// Helper: Window Finder Context
struct WindowSearch {
    DWORD pid;
    HWND hwnd;
};

// Helper: EnumWindows Callback
static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    WindowSearch* search = reinterpret_cast<WindowSearch*>(lParam);
    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);

    // We look for the visible, top-level window of the process
    if (processId == search->pid && IsWindowVisible(hwnd)) {
        search->hwnd = hwnd;
        return FALSE; // Stop enumeration (found it)
    }
    return TRUE; // Keep looking
}

DiagnosisType Investigator::ProbeHungWindow(DWORD pid) {
    if (pid == 0 || pid == 4) return DiagnosisType::None;

    // 1. Find the Main Window
    WindowSearch search = { pid, NULL };
    EnumWindows(EnumWindowsCallback, (LPARAM)&search);

    if (!search.hwnd) {
        return DiagnosisType::None; // No window (Background service or console), cannot probe UI hang
    }

    // 2. OS Heuristic Check
    if (IsHungAppWindow(search.hwnd)) {
        return DiagnosisType::Process_Deadlocked; // OS already knows it's dead
    }

    // 3. Active Interrogation (Ping)
    // Candidate 2: "Send a WM_NULL message to the window (0-impact ping)."
    DWORD_PTR result;
    LRESULT lr = SendMessageTimeout(
        search.hwnd, 
        WM_NULL, 
        0, 
        0, 
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 
        250, // 250ms timeout (aggressive check)
        &result
    );

    if (lr == 0) {
        // Function failed or timed out
        if (GetLastError() == ERROR_TIMEOUT) {
            return DiagnosisType::Process_Deadlocked; // Window is frozen
        }
    }

    return DiagnosisType::None; // Window is responsive
}

// [PATCH] Async Implementation
std::future<InvestigationVerdict> Investigator::DiagnoseAsync(const GovernorDecision& govState) {
    // Capture govState by value to ensure thread safety when running in background
    return std::async(std::launch::async, [this, govState]() {
        return this->Diagnose(govState);
    });
}

DiagnosisType Investigator::ProbeWorkloadChange(DWORD pid, DWORD baselineThreadCount) {
    if (pid == 0 || pid == 4) return DiagnosisType::None;

    // Candidate 1: "Did the target process spawn new threads... since the action?"
    
    // [RAII] Snapshot
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!hSnap) return DiagnosisType::None;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap.get(), &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                // Found our process
                DWORD currentThreads = pe32.cntThreads;

                // Candidate 1: "If ThreadCount increased by >10%: Diagnosis = Workload Change."
                if (baselineThreadCount > 0) {
                    double increase = (double)currentThreads / (double)baselineThreadCount;
                    if (increase > 1.10) {
                        return DiagnosisType::External_Interference; // It's not our fault, user added work.
                    }
                }
                break;
            }
        } while (Process32Next(hSnap.get(), &pe32));
    }

    return DiagnosisType::None;
}

DiagnosisType Investigator::ProbeWaitChain(DWORD pid) {
    // [SAFETY] Invalid PID check
    if (pid == 0 || pid == 4) return DiagnosisType::None;

    WctSession session;
    if (!session.IsValid()) {
        return DiagnosisType::None; // WCT not supported or permission denied
    }

    // [RAII] Snapshot of threads
    UniqueHandle hThreadSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    // [FIX] Check for INVALID_HANDLE_VALUE specifically
    if (hThreadSnap.get() == INVALID_HANDLE_VALUE) {
        return DiagnosisType::None;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    // Use .get() for raw handle access
    if (!Thread32First(hThreadSnap.get(), &te32)) {
        return DiagnosisType::None;
    }

    int threadsChecked = 0;
    constexpr int MAX_THREADS_TO_CHECK = 16; // Limit to avoid performance penalty

    // Iterate through threads
    do {
        if (te32.th32OwnerProcessID == pid) {
            WAITCHAIN_NODE_INFO nodes[WCT_MAX_NODE_COUNT];
            DWORD nodeCount = WCT_MAX_NODE_COUNT;
            BOOL isCycle = FALSE;

            // Analyze wait chain for this thread
            if (GetThreadWaitChain(session.Get(),
                                   NULL,
                                   WCT_OUT_OF_PROC_FLAG,
                                   te32.th32ThreadID,
                                   &nodeCount,
                                   nodes,
                                   &isCycle)) 
            {
                if (isCycle) {
                    // [CRITICAL] Deadlock detected!
                    // The thread is waiting for a resource held by another thread in a cycle.
                    return DiagnosisType::Process_Deadlocked;
                }

                // Analyze nodes for frozen I/O
                for (DWORD i = 0; i < nodeCount; ++i) {
                    if (nodes[i].ObjectStatus == WctStatusBlocked) {
                         // [FIX] Deep Analysis: Log IPC/RPC Blockages
                         if (nodes[i].ObjectType == WctAlpcType || nodes[i].ObjectType == WctComType) {
                              Log("[INV] Thread " + std::to_string(te32.th32ThreadID) + 
                                  " Blocked on IPC/RPC. Potential Deadlock.");
                         }
                    }
                }
            }
            
            threadsChecked++;
            if (threadsChecked >= MAX_THREADS_TO_CHECK) break;
        }
    } while (Thread32Next(hThreadSnap.get(), &te32));

    return DiagnosisType::None; // No obvious deadlock found
}

DiagnosisType Investigator::ProbeDiskThrashing(DWORD pid) {
    // [SAFETY] Invalid PID check
    if (pid == 0 || pid == 4) return DiagnosisType::None;

    UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!hProcess) return DiagnosisType::None;

    IO_COUNTERS io1, io2;
    if (!GetProcessIoCounters(hProcess.get(), &io1)) return DiagnosisType::None;

    // Sample window (100ms as per Candidate 1)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (!GetProcessIoCounters(hProcess.get(), &io2)) return DiagnosisType::None;

    uint64_t readOpsDelta  = io2.ReadOperationCount - io1.ReadOperationCount;
    uint64_t writeOpsDelta = io2.WriteOperationCount - io1.WriteOperationCount;
    uint64_t readBytesDelta = io2.ReadTransferCount - io1.ReadTransferCount;
    uint64_t writeBytesDelta = io2.WriteTransferCount - io1.WriteTransferCount;

    uint64_t totalOps = readOpsDelta + writeOpsDelta;
    uint64_t totalBytes = readBytesDelta + writeBytesDelta;

    // Heuristic 1: Idle Check
    if (totalOps < 5) return DiagnosisType::None; // Not enough activity to judge

    // Heuristic 2: Average Transfer Size
    double avgTransferSize = (double)totalBytes / totalOps;

    // "If TransferSize < 8KB ... Diagnosis = Thrashing."
    // "If TransferSize > 1MB ... Diagnosis = Streaming."
    
    if (avgTransferSize < 8192) {
        // High frequency, small IO = Random Seek / Thrashing Risk
        return DiagnosisType::IO_Thrashing; 
    }
    
    // Streaming (Safe to trim, usually) - Not a "Danger" diagnosis, so we return None or specific Safe type
    // For now, we only flag Dangers.
    
    return DiagnosisType::None;
}
