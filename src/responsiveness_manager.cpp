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

#include "responsiveness_manager.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "performance.h" 
#include <thread>
#include <filesystem>

ResponsivenessManager& ResponsivenessManager::Get() {
    static ResponsivenessManager instance;
    return instance;
}

void ResponsivenessManager::Update() {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    // MASTER TOGGLE: Check configuration
    if (!g_responsivenessRecoveryEnabled.load()) {
        if (m_state.pid != 0) {
            if (m_state.boosted) Revert();
            Reset();
        }
        return;
    }

    // GLOBAL CONSTRAINT: Disabled if Game Boost active
    if (g_perfGuardian.HasActiveSessions()) {
        if (m_state.boosted) Revert();
        Reset();
        return;
    }

    HWND hFg = GetForegroundWindow();
    if (!hFg) {
        // Focus lost or desktop, ensure we don't leave a boost hanging
        if (m_state.boosted) Revert();
        return;
    }

    // Detection
    // Signal 1: IsHungAppWindow (OS heuristic: no msg processing for 5s)
    bool isHung = IsWindowHung(hFg);

    if (isHung) {
        DWORD pid = 0;
        DWORD tid = GetWindowThreadProcessId(hFg, &pid);
        if (pid == 0) return;

        // SAFETY: Self-Exclusion (Robust against renaming)
        if (pid == GetCurrentProcessId()) return;

        // SAFETY: Exclude Critical System Processes
        // Optimization: Only do expensive checks if it's not us
        UniqueHandle hProcCheck(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProcCheck) {
            wchar_t path[MAX_PATH];
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcCheck.get(), 0, path, &sz)) {
                std::wstring name = ExeFromPath(path);
                if (IsSystemCriticalProcess(name)) return;
            }
        }

        uint64_t now = GetTickCount64();

        if (m_state.pid != pid) {
            // New hang detected
            Reset();
            m_state.pid = pid;
            m_state.hwnd = hFg;
            m_state.hangStartTime = now;
            // Log("[RESPONSIVE] Potential hang detected: PID " + std::to_string(pid));
        } else {
            // Persistent hang
            uint64_t duration = now - m_state.hangStartTime;

            // Soft Recovery Boost (> 2 seconds of hang)
            if (duration > 2000 && !m_state.boosted) {
                ApplySoftBoost(pid, tid);
            }

            // User-Controlled Recovery (> 15 seconds)
            if (duration > 15000 && !m_state.prompted && m_state.boosted) {
                // One-time prompt per hang instance
                m_state.prompted = true; 
                
                // Check user preference for prompts
                if (!g_recoveryPromptEnabled.load()) return;

                // Dispatch to background worker to avoid blocking the main loop
                std::thread([pid, this]() {
                    std::wstring name = this->GetProcessName(pid);
                    std::wstring wName = name.empty() ? L"Application" : name;
                    std::wstring msg = wName + L" is not responding.\n\nPMAN can attempt to restart it, or you can wait.";
                    
                    int result = MessageBoxW(nullptr, msg.c_str(), L"Responsiveness Recovery", MB_ABORTRETRYIGNORE | MB_ICONWARNING | MB_TOPMOST);
                    
                    if (result == IDABORT) {
                        // User chose to kill/restart
                        UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
                        if (hProc) {
                            TerminateProcess(hProc.get(), 1);
                            Log("[RESPONSIVE] User terminated hung process PID " + std::to_string(pid));
                        }
                    }
                }).detach();
            }
        }
    } else {
        // Observation & Revert
        // Window is responsive. If we were tracking it, revert changes.
        if (m_state.pid != 0) {
            if (m_state.boosted) {
                Revert();
                Log("[RESPONSIVE] Application recovered. Boosts reverted for PID " + std::to_string(m_state.pid));
            }
            Reset();
        }
    }
}

void ResponsivenessManager::ApplySoftBoost(DWORD pid, DWORD tid) {
    // Safe Intervention: HIGH_PRIORITY (Not Realtime) + Thread Boost
    Log("[RESPONSIVE] Applying soft recovery boost to PID " + std::to_string(pid));
    
    m_state.originalPriority = NORMAL_PRIORITY_CLASS; // Default assumption
    
    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (hProc) {
        m_state.originalPriority = GetPriorityClass(hProc.get());
        // Hard Limit: Do not boost if already High or Realtime
        if (m_state.originalPriority < HIGH_PRIORITY_CLASS) {
            SetPriorityClass(hProc.get(), HIGH_PRIORITY_CLASS);
        }
        
        // Temporary Affinity Expansion (Allow all cores)
        DWORD_PTR processAffinity, systemAffinity;
        if (GetProcessAffinityMask(hProc.get(), &processAffinity, &systemAffinity)) {
            if (processAffinity != systemAffinity) {
                SetProcessAffinityMask(hProc.get(), systemAffinity);
            }
        }
    }

    // Boost UI Thread
    UniqueHandle hThread(OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid));
    if (hThread) {
        m_state.originalThreadPriority = GetThreadPriority(hThread.get());
        if (m_state.originalThreadPriority < THREAD_PRIORITY_HIGHEST) {
            SetThreadPriority(hThread.get(), THREAD_PRIORITY_HIGHEST);
        }
    }
    
    m_state.boosted = true;
}

void ResponsivenessManager::Revert() {
    if (m_state.pid == 0) return;

    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION, FALSE, m_state.pid));
    if (hProc) {
        SetPriorityClass(hProc.get(), m_state.originalPriority);
    }

    if (m_state.hwnd) {
        DWORD tid = GetWindowThreadProcessId(m_state.hwnd, nullptr);
        UniqueHandle hThread(OpenThread(THREAD_SET_INFORMATION, FALSE, tid));
        if (hThread) {
            SetThreadPriority(hThread.get(), m_state.originalThreadPriority);
        }
    }
}

void ResponsivenessManager::Reset() {
    m_state = HungState{};
}

std::wstring ResponsivenessManager::GetProcessName(DWORD pid) {
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (hProc) {
        wchar_t path[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc.get(), 0, path, &sz)) {
            return std::filesystem::path(path).filename().wstring();
        }
    }
    return L"";
}
