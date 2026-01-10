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

#include "input_guardian.h"
#include "logger.h"
#include "utils.h"
#include "globals.h" // For g_userPaused
#include <tlhelp32.h>

InputGuardian g_inputGuardian;

void InputGuardian::Initialize() {
    m_active = true;
    m_dwmPid = GetDwmProcessId();
    Log("[INPUT] Input Responsiveness Guard Initialized");
}

void InputGuardian::Shutdown() {
    m_active = false;
}

void InputGuardian::OnInput(DWORD msgTime) {
    if (!m_active || g_userPaused.load()) return;

    // 1. Monitor Latency
    // msgTime is the timestamp when the input event was generated (driver/OS level).
    // GetTickCount() is now (application processing level).
    DWORD now = GetTickCount();
    
    // Handle wrap-around or future timestamps gracefully
    if (now >= msgTime) {
        DWORD latency = now - msgTime;
        
        // Log significant input lag (>50ms is perceptible)
        if (latency > 50) {
            static uint64_t lastLog = 0;
            uint64_t now64 = GetTickCount64();
            if (now64 - lastLog > 2000) { // Rate limit logging
                Log("[INPUT] High Input Latency Detected: " + std::to_string(latency) + "ms");
                lastLog = now64;
            }
        }
    }

    // 2. Apply Boosts (Throttled)
    // We don't want to spam OpenThread every millisecond on high-poll mice.
    // 500ms cooldown ensures we re-apply boost if it was lost, but not constantly.
    uint64_t now64 = GetTickCount64();
    if (now64 - m_lastBoostTime > 500) {
        ApplyResponsivenessBoost();
        m_lastBoostTime = now64;
    }
}

void InputGuardian::ApplyResponsivenessBoost() {
    // A. Foreground App Boost
    HWND hFg = GetForegroundWindow();
    if (hFg) {
        DWORD pid = 0;
        DWORD tid = GetWindowThreadProcessId(hFg, &pid);
        
        if (tid != 0) {
            BoostThread(tid, "Foreground");
        }
    }

    // B. DWM Boost (Only when input detected)
    BoostDwmProcess();
}

void InputGuardian::BoostThread(DWORD tid, const char* debugTag) {
    // THREAD_SET_INFORMATION is required for SetThreadPriorityBoost
    // THREAD_QUERY_INFORMATION is good practice to verify handle
    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (hThread) {
        // DisablePriorityBoost = FALSE means "Dynamic Boost IS ENABLED".
        // This ensures the OS can boost this thread when it leaves wait states (e.g. input available).
        // Some "optimizers" or background modes might disable this; we enforce it ON.
        if (!SetThreadPriorityBoost(hThread, FALSE)) {
            // Improve: Log failure using the debug tag for diagnostics
            Log("[INPUT] Failed to boost " + std::string(debugTag) + " thread " + 
                std::to_string(tid) + " Error: " + std::to_string(GetLastError()));
        } 
        CloseHandle(hThread);
    }
}

void InputGuardian::BoostDwmProcess() {
    // Fix: Cache DWM threads to avoid high-frequency snapshotting (2000+ threads)
    static std::vector<DWORD> cachedThreads;
    static uint64_t lastCacheUpdate = 0;

    // Refresh DWM PID occasionally in case of crash/restart
    uint64_t now = GetTickCount64();
    if (now - m_lastDwmScan > 10000 || m_dwmPid == 0) {
        m_dwmPid = GetDwmProcessId();
        m_lastDwmScan = now;
    }

    if (m_dwmPid == 0) return;

    // [PERF FIX] Rate limit actual boosting to 5s (prevents syscall storm)
    static uint64_t lastBoostApply = 0;
    if (now - lastBoostApply < 5000) return;
    lastBoostApply = now;

    // Update thread cache only every 30s
    if (now - lastCacheUpdate > 30000 || cachedThreads.empty()) {
        cachedThreads.clear();
        UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (hSnap.get() != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = {sizeof(te)};
            if (Thread32First(hSnap.get(), &te)) {
                do {
                    if (te.th32OwnerProcessID == m_dwmPid) {
                        cachedThreads.push_back(te.th32ThreadID);
                    }
                } while (Thread32Next(hSnap.get(), &te));
            }
        }
        lastCacheUpdate = now;
    }

    // Boost cached threads
    for (DWORD tid : cachedThreads) {
        BoostThread(tid, "DWM");
    }
}
