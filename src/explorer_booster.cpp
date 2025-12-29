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

void ExplorerBooster::OnTick() {
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
    // If m_gameOrBrowserActive is true but no foreground window, auto-reset
    if (m_gameOrBrowserActive.load()) {
        HWND fg = GetForegroundWindow();
        if (!fg) {
            DWORD fgPid = 0;
            GetWindowThreadProcessId(fg, &fgPid);
            if (fgPid == 0) {
                LogState("SAFETY RESET: No foreground window detected, clearing lock", 0);
                OnGameStop(); // Force reset the stuck flag
            }
        }
    }

    // CRITICAL FIX: Check if browser/game actually still exists
    if (m_gameOrBrowserActive.load()) {
        HWND fg = GetForegroundWindow();
        if (fg) {  // FIX: Only check if we HAVE a foreground window
            DWORD fgPid = 0;
            GetWindowThreadProcessId(fg, &fgPid);
            if (fgPid == 0) {
                LogState("SAFETY RESET: No foreground PID detected, clearing lock", 0);
                OnGameStop(); // Force reset the stuck flag
            }
        } else {
            // No foreground window at all - definitely safe to reset
            LogState("SAFETY RESET: No foreground window, clearing lock", 0);
            OnGameStop();
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
    if (now - m_lastScanMs > scanInterval) {
        ScanShellProcesses();
        m_lastScanMs = now;
    }

    // 2. Update State Machine
    UpdateBoostState();
}

void ExplorerBooster::OnGameStart(DWORD gamePid) {
    m_gameOrBrowserActive = true;
    
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
    // CRITICAL FIX: Forcefully reset the flag
    bool wasActive = m_gameOrBrowserActive.exchange(false);
    
    // Force immediate transition to IDLE_BOOSTED (Post-Game Recovery)
    // We don't wait for the idle timer here. We assume if a game just closed,
    // the user wants the desktop to be responsive IMMEDIATELY.
    std::lock_guard lock(m_mtx);
    if (m_currentState == ExplorerBoostState::LockedOut) {
        m_currentState = ExplorerBoostState::IdleBoosted;
        
        // Apply boosts immediately to recover from paging lag
        for (auto& [pid, instance] : m_instances) {
            ApplyBoosts(pid, ExplorerBoostState::IdleBoosted);
        }
        
        // Log state transitions
        // We force this log because it's a major state change (User Experience)
        LogState("Game stopped - Instant Post-Game Boost ACTIVATED", 0);
    } 
    else if (wasActive && m_config.debugLogging) {
        LogState("Lockout released", 0);
    }
}

void ExplorerBooster::OnBrowserStart(DWORD browserPid) {
    // Treat browser similar to game (no boosts) to prevent resource contention
    m_gameOrBrowserActive = true; 
    OnGameStart(browserPid);
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
    bool shouldBoost = ShouldBoostNow();
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
    
    auto it = m_instances.find(pid);
    if (it == m_instances.end()) return;
    HANDLE hProcess = it->second.handle.get();

    PROCESS_MEMORY_COUNTERS pmc;
    if (!GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) return;
    
    SIZE_T currentWS = pmc.WorkingSetSize;
    // Don't let it shrink below 64MB, or current size if larger
    SIZE_T minWS = (currentWS > 64 * 1024 * 1024) ? currentWS : 64 * 1024 * 1024;
    // Allow some growth
    SIZE_T maxWS = minWS + 128 * 1024 * 1024;
    
    // QUOTA_LIMITS_HARDWS_MIN_ENABLE (0x1) | QUOTA_LIMITS_HARDWS_MAX_DISABLE (0x8)
    DWORD flags = 0x00000001 | 0x00000008; 
    
    if (SetProcessWorkingSetSizeEx(hProcess, minWS, maxWS, flags)) {
        // SUCCESS: Do nothing. (Silence the spam)
        // We verified this works via previous debug logs.
    } else {
        // FAILURE: Log this, as it indicates a problem (e.g. permission loss)
        Log("[EXPLORER] Memory Guard FAILED for PID " + std::to_string(pid) + 
            " Error: " + std::to_string(GetLastError()));
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