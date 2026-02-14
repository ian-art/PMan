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
#include "context.h"
#include <tlhelp32.h>
#include <vector>
#include <filesystem>
#include <algorithm>

// Removed global instance (Now in PManContext)

// Low-Level Keyboard Hook
// Blocks Windows Key (Left/Right) when Game Mode is active
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* p = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        if (p->vkCode == VK_LWIN || p->vkCode == VK_RWIN) {
            // Eat the key message
            return 1;
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// Destructor to ensure thread safety
InputGuardian::~InputGuardian() {
    Shutdown();
    if (m_worker.joinable()) m_worker.join();
    if (m_hookThread.joinable()) m_hookThread.join();
}

void InputGuardian::Initialize() {
    m_active = true;
    m_dwmPid = GetDwmProcessId();
    
    // Capture original accessibility states (Sticky/Filter/Toggle keys)
    SystemParametersInfoW(SPI_GETSTICKYKEYS, sizeof(m_startupSticky), &m_startupSticky, 0);
    SystemParametersInfoW(SPI_GETTOGGLEKEYS, sizeof(m_startupToggle), &m_startupToggle, 0);
    SystemParametersInfoW(SPI_GETFILTERKEYS, sizeof(m_startupFilter), &m_startupFilter, 0);

    Log("[INPUT] Input Responsiveness Guard Initialized");
}

void InputGuardian::Shutdown() {
    m_active = false;
    SetGameMode(false); // Ensure hooks/settings are restored
}

void InputGuardian::UpdateHookTargets(const std::unordered_set<std::wstring>& targets) {
    std::lock_guard<std::mutex> lg(m_cacheMtx); // Reuse existing mutex or add a new one?
    // Note: m_hookTargets access should technically be protected, but for this specific context 
    // (writes happen rarely on config thread, reads on main thread), assignment is atomic enough for sets.
    m_hookTargets = targets;
}

// Helper to get process name for hook validation
static std::wstring GetActiveProcessName() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return L"";
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return L"";
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";
    
    wchar_t buffer[MAX_PATH];
    DWORD size = MAX_PATH;
    std::wstring name = L"";
    if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
        name = std::filesystem::path(buffer).filename().wstring();
    }
    CloseHandle(hProcess);
    return name;
}

void InputGuardian::SetGameMode(bool enabled) {
    bool shouldBlock = false;

    if (enabled) {
        // Selective Blocking
        // Lock required because m_hookTargets might be updating from the Config thread
        std::lock_guard<std::mutex> lg(m_cacheMtx);

        // Only enable hook if the current process is in the explicit block list.
        if (m_hookTargets.empty()) {
            shouldBlock = false; // Default: OFF (User Request)
        } else {
            // [OPTIMIZATION] Do the expensive string logic only if we have targets
            std::wstring currentProc = GetActiveProcessName();
            if (!currentProc.empty()) {
                std::transform(currentProc.begin(), currentProc.end(), currentProc.begin(), towlower);
                if (m_hookTargets.count(currentProc)) {
                    shouldBlock = true;
                }
            }
        }
    }

    if (m_blockingEnabled == shouldBlock) return;
    ToggleInterferenceBlocker(shouldBlock);
}

void InputGuardian::ToggleInterferenceBlocker(bool enable) {
    if (enable) {
        // 1. Disable Windows Key Hook (Moved to dedicated thread to prevent input lag)
        if (!m_hookThread.joinable()) {
            m_hookThread = std::thread([this]() {
                // [AUDIT] CRITICAL: Raise priority to TIME_CRITICAL. 
                // A normal priority hook thread will be preempted by games, causing massive input lag.
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

                // RAII Wrapper for Hook Safety
                // Ensures UnhookWindowsHookEx is ALWAYS called, even on exception or thread termination.
                struct HookGuard {
                    HHOOK h;
                    HookGuard(HHOOK _h) : h(_h) {}
                    ~HookGuard() { if (h) UnhookWindowsHookEx(h); }
                };

                // Install Hook on this dedicated thread
                HHOOK hRaw = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(nullptr), 0);
                HookGuard hook(hRaw); // Lifecycle managed by stack unwinding

                m_hookThreadId = GetCurrentThreadId();

                MSG msg;
                // Pump messages to keep hook alive
                while (GetMessage(&msg, nullptr, 0, 0)) {
                    if (msg.message == WM_QUIT) break;
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }

                m_hookThreadId = 0;
                // HookGuard destructor called here automatically
            });
            // Mark as enabled locally using a dummy handle
            m_hKeyHook = (HHOOK)0x1; 
        }

        // 2. Disable Sticky Keys / Filter Keys Hotkeys
        // FIX: Set flags to 0 to disable Hotkeys AND Confirmations. 
        // SKF_CONFIRMHOTKEY actually *enables* the dialog, which we want to avoid.
        STICKYKEYS sk = { sizeof(STICKYKEYS), 0 };
        sk.dwFlags = 0; 
        SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(sk), &sk, 0);

        TOGGLEKEYS tk = { sizeof(TOGGLEKEYS), 0 };
        tk.dwFlags = 0;
        SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(tk), &tk, 0);

        FILTERKEYS fk = { sizeof(FILTERKEYS), 0 };
        fk.dwFlags = 0;
        SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(fk), &fk, 0);

        Log("[INPUT] Game Mode: Blocked Windows Key & Sticky Keys");
    } else {
        // 1. Remove Hook (Signal thread to quit)
        if (m_hookThread.joinable()) {
            DWORD tid = m_hookThreadId.load();
            if (tid != 0) PostThreadMessageW(tid, WM_QUIT, 0, 0);
            m_hookThread.join();
            m_hKeyHook = nullptr;
        }

        // 2. Restore Original Accessibility Settings
        SystemParametersInfoW(SPI_SETSTICKYKEYS, sizeof(m_startupSticky), &m_startupSticky, 0);
        SystemParametersInfoW(SPI_SETTOGGLEKEYS, sizeof(m_startupToggle), &m_startupToggle, 0);
        SystemParametersInfoW(SPI_SETFILTERKEYS, sizeof(m_startupFilter), &m_startupFilter, 0);

        Log("[INPUT] Game Mode: Restored Input Settings");
    }
    m_blockingEnabled = enable;
}

void InputGuardian::OnInput(DWORD msgTime) {
    if (!m_active || PManContext::Get().isPaused.load()) return;

    DWORD now = static_cast<DWORD>(GetTickCount64());
    
    if (now >= msgTime) {
        DWORD latency = now - msgTime;
        if (latency > 50) {
            static uint64_t lastLog = 0;
            uint64_t now64 = GetTickCount64();
            if (now64 - lastLog > 2000) { 
                Log("[INPUT] High Input Latency Detected: " + std::to_string(latency) + "ms");
                lastLog = now64;
            }
        }
    }

    uint64_t now64 = GetTickCount64();
    if (now64 - m_lastBoostTime > 500) {
        ApplyResponsivenessBoost();
        m_lastBoostTime = now64;
    }
}

void InputGuardian::ApplyResponsivenessBoost() {
    HWND hFg = GetForegroundWindow();
    if (hFg) {
        DWORD pid = 0;
        DWORD tid = GetWindowThreadProcessId(hFg, &pid);
        // Optimization: Only boost if focus changed to a new thread
        if (tid != 0 && tid != m_lastForegroundTid) {
            BoostThread(tid, "Foreground");
            m_lastForegroundTid = tid;
        }
    }
    BoostDwmProcess();
}

void InputGuardian::BoostThread(DWORD tid, const char* debugTag) {
    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (hThread) {
        if (!SetThreadPriorityBoost(hThread, FALSE)) {
            Log("[INPUT] Failed to boost " + std::string(debugTag) + " thread " + 
                std::to_string(tid) + " Error: " + std::to_string(GetLastError()));
        } 
        CloseHandle(hThread);
    }
}

void InputGuardian::BoostDwmProcess() {
    // Static cache for DWM threads
    static std::vector<DWORD> cachedThreads;
    static std::mutex cacheMtx;
    static uint64_t lastCacheUpdate = 0;
    static std::atomic<bool> isUpdating = false;

    uint64_t now = GetTickCount64();
    
    // Refresh PID periodically
    if (now - m_lastDwmScan > 10000 || m_dwmPid == 0) {
        m_dwmPid = GetDwmProcessId();
        m_lastDwmScan = now;
    }

    if (m_dwmPid == 0) return;

    // Trigger update only every 60s or if empty
    if (!isUpdating && (now - lastCacheUpdate > 60000 || cachedThreads.empty())) {
        
        // Ensure previous worker is cleaned up
        if (m_worker.joinable()) {
            m_worker.join();
        }

        isUpdating = true;
        DWORD targetPid = m_dwmPid;
        
        // Capture 'this' to call BoostThread inside the worker
        // Safety: Destructor joins m_worker, so 'this' is guaranteed valid
        m_worker = std::thread([this, targetPid]() {
            std::vector<DWORD> newThreads;
            UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            
            if (hSnap.get() != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te = {sizeof(te)};
                te.dwSize = sizeof(te); // Good practice
                if (Thread32First(hSnap.get(), &te)) {
                    do {
                        if (te.th32OwnerProcessID == targetPid) {
                            newThreads.push_back(te.th32ThreadID);
                        }
                    } while (Thread32Next(hSnap.get(), &te));
                }
            }

            // Apply boosts IMMEDIATELY in the background thread.
            // Priority boost state is persistent; we don't need to re-apply it 
            // every frame on the main thread, only when we find threads.
            for (DWORD tid : newThreads) {
                BoostThread(tid, "DWM");
            }
            
            {
                std::lock_guard<std::mutex> lock(cacheMtx);
                cachedThreads = std::move(newThreads);
                lastCacheUpdate = GetTickCount64();
            }
            isUpdating = false;
        });
    }
    
    // Main thread does NOTHING. 
    // Optimization: Removed synchronous loop that opened ~15 handles every 500ms.
}
