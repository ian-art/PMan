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

#include "explorer_booster.h"
#include "logger.h"
#include "globals.h" // For g_idleRevertEnabled etc.
#include "tweaks.h" // For SetProcessIoPriority
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "Psapi.lib")

void ExplorerBooster::Initialize() {
    // If anti-cheat is running, auto-disable risky features
    if (IsAntiCheatProtected(GetCurrentProcessId())) {
        Log("[EXPLORER] Anti-cheat detected - disabling I/O priority boosts");
        m_config.boostIoPriority = false;
    }
    
    // Must have Admin for DWM
    if (m_config.boostDwm && !EnableDebugPrivilege()) {
        Log("[EXPLORER] Admin rights required for DWM. Disabling DWM boost.");
        m_config.boostDwm = false;
    }

    m_active = true;
    m_lastUserActivityMs = GetTickCount64();
    Log("[EXPLORER] Initialized Smart Shell Booster");
}

void ExplorerBooster::Shutdown() {
    m_active = false;
    std::lock_guard lock(m_mtx);
    for (auto& [pid, instance] : m_instances) {
        RevertBoosts(pid);
    }
    m_instances.clear();
}

void ExplorerBooster::UpdateConfig(const ExplorerConfig& cfg) {
    std::lock_guard lock(m_mtx);
    m_config = cfg;
}

uint32_t ExplorerBooster::GetIdleThreshold() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_config.idleThresholdMs;
}

void ExplorerBooster::OnTick() {
    if (g_userPaused.load()) return;
    // CAPTURE CONFIG SAFELY AT START OF TICK
    bool enabled = false;
    bool debug = false;
    uint32_t scanInterval = 5000;

    {
        std::lock_guard lock(m_mtx);
        enabled = m_config.enabled;
        debug = m_config.debugLogging;
        scanInterval = m_config.scanIntervalMs;
    }

    if (!enabled || !m_active) return;

    uint64_t now = GetTickCount64();

	// CRITICAL FIX: Check if browser/game actually still exists
    if (m_gameOrBrowserActive.load()) {
        HWND fg = GetForegroundWindow(); // Cache result to avoid double syscall
        
        if (!fg) {
            // No foreground window at all - definitely safe to reset
            LogState("SAFETY RESET: No foreground window detected, clearing lock", 0);
            OnGameStop(); 
        } 
        else {
            DWORD fgPid = 0;
            GetWindowThreadProcessId(fg, &fgPid);
            if (fgPid == 0) {
                LogState("SAFETY RESET: No foreground PID detected, clearing lock", 0);
                OnGameStop();
            }
        }
    }

    // Rate-limited debug logging for tick calls (only if debug enabled)
    // FIX: Use local 'debug' variable to ensure config change visibility
    static uint64_t lastTickLog = 0;
    if (debug && (now - lastTickLog >= 1000)) {
        Log(("[TICK] OnTick() called, active=" + std::to_string(m_active) + 
             ", gameOrBrowserActive=" + std::to_string(m_gameOrBrowserActive.load()) + 
             ", scanInterval=" + std::to_string(scanInterval)).c_str());
        lastTickLog = now;
    }

	// 1. Scan for new processes periodically
    // FIX: Use local 'scanInterval' variable
    // OPTIMIZATION: Do not scan if we are locked out (game active) or system is not idle
    if (!m_gameOrBrowserActive.load() && m_currentState != ExplorerBoostState::LockedOut) {
        // Exponential backoff: if we haven't seen activity for a long time, scan less frequently
        uint32_t effectiveInterval = (now - m_lastUserActivityMs.load() > 60000) ? 30000 : scanInterval;

        if (now - m_lastScanMs > effectiveInterval) {
            ScanShellProcesses();
            m_lastScanMs = now;
        }
    }

    // 2. Update State Machine
    UpdateBoostState();
}

void ExplorerBooster::OnGameStart(DWORD gamePid) {
    m_gameOrBrowserActive = true;
    m_isGameSession = true; // Mark as Game Session (High Priority Resume)
    
    // Immediate pre-emptive revert
    std::lock_guard lock(m_mtx);
    if (m_currentState != ExplorerBoostState::LockedOut) {
        LogState("Game Start detected - Instant Revert", gamePid);
        m_currentState = ExplorerBoostState::LockedOut;
        for (auto& [pid, instance] : m_instances) {
            RevertBoosts(pid);
        }
    }
}

void ExplorerBooster::OnGameStop() {
    // 1. Atomically grab and reset the activity flag
    bool wasActive = m_gameOrBrowserActive.exchange(false);
    
    std::lock_guard lock(m_mtx);
    
    // 2. LOGIC FIX: Check Session Type for Resume Strategy
    if (wasActive || m_currentState == ExplorerBoostState::LockedOut) {
        
        if (m_isGameSession) {
            // CASE A: GAMING SESSION ENDED - Boost IMMEDIATELY
            m_currentState = ExplorerBoostState::IdleBoosted;
            
            for (auto& [pid, instance] : m_instances) {
                ApplyBoosts(pid, ExplorerBoostState::IdleBoosted);
            }
            Log("[EXPLORER] Game stopped - Instant Post-Game Boost ACTIVATED");
        } 
        else {
            // CASE B: BROWSER SESSION ENDED
            // FIX: Also boost immediately when browser stops
            // User minimized browser to use desktop, so boost desktop!
            m_currentState = ExplorerBoostState::IdleBoosted;
            
            for (auto& [pid, instance] : m_instances) {
                ApplyBoosts(pid, ExplorerBoostState::IdleBoosted);
            }
            Log("[EXPLORER] Browser stopped - Instant Desktop Boost");
        }
    }
    else if (m_config.debugLogging) {
        LogState("No active session detected during stop", 0);
    }
}

void ExplorerBooster::OnBrowserStart(DWORD browserPid) {
    // Treat browser similar to game (no boosts) to prevent resource contention
    m_gameOrBrowserActive = true; 
    m_isGameSession = false; // Mark as Browser Session (Standard Resume)
    
    // Immediate pre-emptive revert
    std::lock_guard lock(m_mtx);
    if (m_currentState != ExplorerBoostState::LockedOut) {
        LogState("Browser Start detected - Instant Revert", browserPid);
        m_currentState = ExplorerBoostState::LockedOut;
        for (auto& [pid, instance] : m_instances) {
            RevertBoosts(pid);
        }
    }
}

void ExplorerBooster::OnUserActivity() {
    m_lastUserActivityMs.store(GetTickCount64(), std::memory_order_relaxed);
    
    // Instant wake-up if we were idle
    if (m_currentState == ExplorerBoostState::IdleBoosted) {
        // Will be handled in next Tick, but we can signal urgency
        m_currentPollIntervalMs = 250; 
    }
}

void ExplorerBooster::ScanShellProcesses() {
    auto currentPids = GetAllShellPIDs();
    std::lock_guard lock(m_mtx);
    
    // Remove dead instances
    for (auto it = m_instances.begin(); it != m_instances.end(); ) {
        if (!IsProcessIdentityValid(it->second.identity)) {
            // Process died?
            it = m_instances.erase(it);
        } else {
            ++it;
        }
    }
    
    // Add new instances with identity tracking
    for (DWORD pid : currentPids) {
        if (m_instances.find(pid) == m_instances.end()) {
            ProcessIdentity identity;
            if (GetProcessIdentity(pid, identity)) {
                ShellInstance instance;
                instance.identity = identity;
                instance.state = ExplorerBoostState::Default;
                instance.lastBoostTimeMs = 0;
                // Open with rights for Priority, Working Set, and EcoQoS
                instance.handle = UniqueHandle(OpenProcess(
                    PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, 
                    FALSE, pid));
                
                if (instance.handle) {
                    m_instances[pid] = std::move(instance);
                    LogState("Tracking new shell process", pid);
                }
            }
        }
    }
}

void ExplorerBooster::UpdateBoostState() {
    // Verbosity CONTROL: Only log state changes, not every tick
    bool shouldBoost = false;
    {
        // FIX: Lock mutex to prevent race condition when reading config in ShouldBoostNow
        std::lock_guard lock(m_mtx);
        shouldBoost = ShouldBoostNow();
    }
    ExplorerBoostState targetState = shouldBoost ? ExplorerBoostState::IdleBoosted : ExplorerBoostState::Default;

	// CRITICAL: Check if we need to transition states
    if (m_currentState != targetState) {
        std::lock_guard lock(m_mtx);
        
        // FORCE LOG: Always log state transitions, regardless of debug_logging setting.
        // We manually construct the message here because LogState() suppresses output when debug is off.
        try {
            std::string msg = "[EXPLORER] ";
            msg += (shouldBoost ? "Entering IDLE_BOOSTED state" : "Entering DEFAULT state");
            msg += " | State=";
            msg += StateToString(m_currentState.load());
            Log(msg);
        } catch (...) {
            // Swallow allocation errors during logging to prevent crashes
        }
        
        m_currentState = targetState;

        // Apply or revert boosts for all tracked processes
        for (auto& [pid, instance] : m_instances) {
            if (shouldBoost) {
                ApplyBoosts(pid, ExplorerBoostState::IdleBoosted);
            } else {
                RevertBoosts(pid);
            }
        }
    } else if (targetState == ExplorerBoostState::IdleBoosted && m_config.preventShellPaging) {
        // Maintain Memory Guard while idle (quietly, no logging)
        std::lock_guard lock(m_mtx);
        for (auto& [pid, instance] : m_instances) {
            EnforceMemoryGuard(pid);
        }
    }
    
    // Log current state ONCE when locked out (not continuously)
    if (m_gameOrBrowserActive && m_config.debugLogging) {
        static uint64_t lastLockLog = 0;
        uint64_t now = GetTickCount64();
        if (now - lastLockLog >= 5000) { // Log every 5 seconds max
            LogState("LOCKED OUT (game/browser active)", 0);
            lastLockLog = now;
        }
    }
}

bool ExplorerBooster::ShouldBoostNow() const {
    // 1. Absolute Priority: No boosts if Game or Browser is active
    if (m_gameOrBrowserActive.load() || g_sessionLocked.load()) {
        return false;
    }

    // 2. "Sticky" Boost (The Fix):
    // If we are already boosted, STAY boosted regardless of mouse movement.
    // This keeps the system responsive while the user interacts with the desktop.
    // The state will only reset if a game/browser launches (checked in step 1).
    if (m_currentState.load() == ExplorerBoostState::IdleBoosted) {
        return true;
    }

    // 3. Initial Activation:
    // Only ENTER the boosted state after the configured idle time.
    // This acts as a "settling time" to avoid rapid toggling.
    uint64_t lastActivity = m_lastUserActivityMs.load();
    uint64_t now = GetTickCount64();
    uint64_t idleDuration = now - lastActivity;

    return idleDuration >= m_config.idleThresholdMs;
}

void ExplorerBooster::ApplyBoosts(DWORD pid, ExplorerBoostState state) {
    auto it = m_instances.find(pid);
    if (it == m_instances.end() || !it->second.handle) return;
    
    HANDLE hProc = it->second.handle.get();
    bool logSuccess = m_config.debugLogging; // Only detailed logs if debug is on

    // 1. Disable Power Throttling (EcoQoS)
    if (m_config.disablePowerThrottling) {
        PROCESS_POWER_THROTTLING_STATE PowerThrottling;
        RtlZeroMemory(&PowerThrottling, sizeof(PowerThrottling));
        PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        PowerThrottling.StateMask = 0; // 0 = Disable Throttling (Boost)
        
        if (SetProcessInformation(hProc, ProcessPowerThrottling, 
                              &PowerThrottling, sizeof(PowerThrottling))) {
            if (logSuccess) Log("[EXPLORER] EcoQoS Disabled (Boosted) for PID " + std::to_string(pid));
        } else {
             Log("[EXPLORER] Failed to disable EcoQoS for PID " + std::to_string(pid) + 
                 " Error: " + std::to_string(GetLastError()));
        }
    }

    // 2. I/O Priority
    if (m_config.boostIoPriority) {
        SetProcessIoPriority(pid, 1); // High
    }

    // 3. Memory Guard
    if (m_config.preventShellPaging) {
        EnforceMemoryGuard(pid);
    }
    
    it->second.state = state;
}

void ExplorerBooster::EnforceMemoryGuard(DWORD pid) {
    if (!m_config.preventShellPaging) return;
    
    // Only enforce on systems with 12GB+ RAM
    MEMORYSTATUSEX ms = { sizeof(ms) };
    if (!GlobalMemoryStatusEx(&ms)) return;
    if ((ms.ullTotalPhys >> 30) < 12) return; // <12GB: skip to avoid paging
    
    auto it = m_instances.find(pid);
    if (it == m_instances.end()) return;
    HANDLE hProcess = it->second.handle.get();

    PROCESS_MEMORY_COUNTERS pmc;
    if (!GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) return;
    
    // Reduce locked memory: 32MB min, 96MB max (was 64-192)
    SIZE_T currentWS = pmc.WorkingSetSize;
    SIZE_T minWS = (currentWS > 32 * 1024 * 1024) ? currentWS : 32 * 1024 * 1024;
    SIZE_T maxWS = minWS + 64 * 1024 * 1024; // 64MB growth headroom
    
    // Soft limits instead of hard: remove HARDWS_MIN flag
    DWORD flags = QUOTA_LIMITS_HARDWS_MAX_DISABLE;
    
    if (SetProcessWorkingSetSizeEx(hProcess, minWS, maxWS, flags)) {
        // SUCCESS: Do nothing. (Silence the spam)
        // We verified this works via previous debug logs.
    } else {
        // FAILURE: Capture error immediately
        DWORD err = GetLastError();
        // Error 5 (Access Denied) is expected for DWM (Protected Process Light) - suppress it
        if (err != ERROR_ACCESS_DENIED) {
            Log("[EXPLORER] Memory Guard FAILED for PID " + std::to_string(pid) + 
                " Error: " + std::to_string(err));
        }
    }
}

void ExplorerBooster::RevertBoosts(DWORD pid) {
    auto it = m_instances.find(pid);
    if (it == m_instances.end() || !it->second.handle) return;

    HANDLE hProc = it->second.handle.get();

    // 1. Re-enable Power Throttling (Default behavior)
    if (m_config.disablePowerThrottling) {
        PROCESS_POWER_THROTTLING_STATE PowerThrottling;
        RtlZeroMemory(&PowerThrottling, sizeof(PowerThrottling));
        PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
        PowerThrottling.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED; // Enable EcoQoS
        
        SetProcessInformation(hProc, ProcessPowerThrottling, 
                              &PowerThrottling, sizeof(PowerThrottling));
    }

    // 2. Restore I/O Priority
    SetProcessIoPriority(pid, 2); // Normal/Low

    // 3. Release Memory Guard
    ReleaseMemoryGuard(pid);

    it->second.state = ExplorerBoostState::Default;
}

void ExplorerBooster::ReleaseMemoryGuard(DWORD pid) {
    // To release, we set limits to (0, 0) incorrectly? No, we just remove the hard limit flags.
    // Or simpler: Just set standard limits without the Hard Min flag.
    auto it = m_instances.find(pid);
    if (it == m_instances.end()) return;
    HANDLE hProcess = it->second.handle.get();
    
    // Soft limits, allow OS to trim
    SIZE_T minWS = 4096; // 4KB
    SIZE_T maxWS = 256 * 1024 * 1024; // Arbitrary high cap
    DWORD flags = 0; // Soft limits
    
    SetProcessWorkingSetSizeEx(hProcess, minWS, maxWS, flags);
}

std::vector<DWORD> ExplorerBooster::GetAllShellPIDs() const {
    std::vector<DWORD> pids;
    
    UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnap.get() == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(hSnap.get(), &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(hSnap.get(), &pe));
    }
    
    if (m_config.boostDwm) {
        DWORD dwmPid = GetDwmProcessId();
        if (dwmPid != 0) pids.push_back(dwmPid);
    }

    return pids;
}

DWORD ExplorerBooster::GetDwmProcessId() const {
    // Method 1: Registry (fastest)
    HKEY hKey;
    DWORD dwmPid = 0;
    DWORD size = sizeof(dwmPid);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
                      L"Software\\Microsoft\\Windows\\DWM", 
                      0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"ProcessId", NULL, NULL, 
                        reinterpret_cast<LPBYTE>(&dwmPid), &size);
        RegCloseKey(hKey);
    }
    
    // Method 2: Fallback
    if (dwmPid == 0) {
        UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(hSnap.get(), &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"dwm.exe") == 0) {
                    return pe.th32ProcessID;
                }
            } while (Process32NextW(hSnap.get(), &pe));
        }
    }
    
    return dwmPid;
}

bool ExplorerBooster::EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) 
        return false;
    
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return result && err == ERROR_SUCCESS;
}

void ExplorerBooster::LogState(const char* action, DWORD pid) const {
    // 1. Check if debug logging is enabled first
    if (!m_config.debugLogging) {
        return;
    }

    try {
        // 2. Use std::string for safe, dynamic string construction.
        // This eliminates fixed-buffer risks (strcat_s crashes) completely.
        std::string msg;
        msg.reserve(128); // Optimization: Pre-allocate reasonable size to minimize reallocs

        msg += "[EXPLORER] ";
        msg += action;
        msg += " | State=";
        msg += StateToString(m_currentState.load());

        if (pid != 0) {
            msg += " PID=";
            msg += std::to_string(pid);
        }

        // 3. Log the safe string
        Log(msg); 
    }
    catch (const std::exception&) {
        // Swallow allocation errors to prevent app crash during logging
    }
}

const char* ExplorerBooster::StateToString(ExplorerBoostState state) const {
    switch (state) {
        case ExplorerBoostState::Default: return "Default";
        case ExplorerBoostState::IdleBoosted: return "IdleBoosted";
        case ExplorerBoostState::LockedOut: return "LockedOut";
        default: return "Unknown";
    }
}
