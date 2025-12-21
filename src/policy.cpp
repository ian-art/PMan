#include "policy.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "tweaks.h"
#include "services.h"
#include <wtsapi32.h>
#include <mutex>

#pragma comment(lib, "Wtsapi32.lib")

using namespace std::string_literals;

int DetectWindowType(HWND hwnd)
{
    if (!hwnd) return 0;
    
    wchar_t title[512] = {};
    wchar_t className[256] = {};
    
    GetWindowTextW(hwnd, title, 512);
    GetClassNameW(hwnd, className, 256);
    
    std::string titleStr = WideToUtf8(title);
    std::string classStr = WideToUtf8(className);
    
    // Convert to lowercase once (optimization)
    asciiLower(titleStr);
    asciiLower(classStr);
    
    std::shared_lock lg(g_setMtx);
    
    // Check game windows (patterns are already lowercase from config)
    for (const auto& pattern : g_gameWindows)
    {
        if (ContainsIgnoreCase(titleStr, pattern) || 
            ContainsIgnoreCase(classStr, pattern))
        {
            return 1;
        }
    }
    
    // Check browser windows
    for (const auto& pattern : g_browserWindows)
    {
        if (ContainsIgnoreCase(titleStr, pattern) || 
            ContainsIgnoreCase(classStr, pattern))
        {
            return 2;
        }
    }
    
    return 0;
}

void CheckAndReleaseSessionLock()
{
    if (!g_sessionLocked.load()) return;
    
    ProcessIdentity lockedIdentity;
    {
        std::lock_guard lock(g_processIdentityMtx);
        lockedIdentity = g_lockedProcessIdentity;
    }

    if (!IsProcessIdentityValid(lockedIdentity))
    {
        DWORD lockedPid = lockedIdentity.pid;
        Log("Session lock RELEASED - process " + std::to_string(lockedPid) + " no longer exists");
        
        g_sessionLocked.store(false);
        g_lockedGamePid.store(0);
        
        {
            std::lock_guard lock(g_processIdentityMtx);
            g_lastProcessIdentity = {0, {0, 0}};
            g_lockedProcessIdentity = {0, {0, 0}};
        }
        
        ResumeBackgroundServices();
    }
}

bool ShouldIgnoreDueToSessionLock(int detectedMode, DWORD /*pid*/)
{
    if (!g_sessionLocked.load()) return false;
    
    if (detectedMode == 2)
    {
        ProcessIdentity lockedIdentity;
        {
            std::lock_guard lock(g_processIdentityMtx);
            lockedIdentity = g_lockedProcessIdentity;
        }
        
        if (IsProcessIdentityValid(lockedIdentity))
        {
            HWND fg = GetForegroundWindow();
            DWORD fgPid = 0;
            GetWindowThreadProcessId(fg, &fgPid);

            if (fgPid == lockedIdentity.pid)
            {
                Log("Session lock ACTIVE - ignoring browser switch (locked to game PID: " +
                    std::to_string(lockedIdentity.pid) + ")");
                return true;
            }
        }
        else
        {
            CheckAndReleaseSessionLock();
            return false;
        }
    }
    
    return false;
}

static bool IsProcessInActiveSession(DWORD pid)
{
    DWORD activeSessionId = WTSGetActiveConsoleSessionId();

    if (activeSessionId == 0xFFFFFFFF)
        return false;

    // CRITICAL: Verify process identity BEFORE checking session
    ProcessIdentity currentIdentity;
    if (!GetProcessIdentity(pid, currentIdentity))
    {
        return false;
    }

    DWORD processSessionId = 0;
    if (!ProcessIdToSessionId(pid, &processSessionId))
    {
        DWORD err = GetLastError();

        if (err == ERROR_ACCESS_DENIED ||
            err == ERROR_INVALID_PARAMETER ||
            err == ERROR_INVALID_HANDLE)
        {
            return false;
        }

        Log("Unexpected ProcessIdToSessionId failure for PID " +
            std::to_string(pid) + ": " + std::to_string(err));
        return false;
    }

    // Verify the PID is still valid
    ProcessIdentity verifyIdentity;
    if (!GetProcessIdentity(pid, verifyIdentity) || 
        verifyIdentity != currentIdentity)
    {
        return false;
    }
    return processSessionId == activeSessionId;
}

bool IsPolicyChangeAllowed(int newMode)
{
    int currentMode = g_lastMode.load();
    if (newMode == currentMode) return true;
    
    // Policy Cooldown / Hysteresis
    static constexpr auto POLICY_COOLDOWN = std::chrono::seconds(5);
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    auto lastChange = g_lastPolicyChange.load();
    
    if (lastChange == 0) return true;
    
    auto elapsed_ms = (now - lastChange) / 1000000;
    auto required_ms = std::chrono::duration_cast<std::chrono::milliseconds>(POLICY_COOLDOWN).count();
    
    if (elapsed_ms >= required_ms) return true;
    
    Log("Policy cooldown active - blocking mode change from " + std::to_string(currentMode) + 
        " to " + std::to_string(newMode) + " (" + std::to_string(elapsed_ms) + "ms elapsed, " + 
        std::to_string(required_ms) + "ms required)");
    return false;
}

void EvaluateAndSetPolicy(DWORD pid, HWND hwnd)
{
    if (!g_running || pid == 0 || pid == GetCurrentProcessId()) return;
    
    // Session-scoped filtering
    if (!hwnd && g_ignoreNonInteractive.load() && !g_sessionLocked.load())
    {
        if (!IsProcessInActiveSession(pid))
        {
            return;
        }
    }
    
    CheckAndReleaseSessionLock();
    
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    
    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    BOOL success = QueryFullProcessImageNameW(h, 0, path, &sz);
    CloseHandle(h);
    
    if (!success) return;
    
    std::string exe = ExeFromPath(path);
    if (exe.empty()) return;

    int mode = 0;
    
    if (hwnd)
    {
        mode = DetectWindowType(hwnd);
        if (mode != 0)
        {
            Log("Window detection: " + exe + " detected via window " + 
                (mode == 1 ? "(GAME)" : "(BROWSER)"));
        }
    }
    
    if (mode == 0)
    {
        std::shared_lock lg(g_setMtx);
        if (g_games.count(exe))   mode = 1;
        else if (g_browsers.count(exe)) mode = 2;
    }
    
    if (mode == 0) return;
    
    if (ShouldIgnoreDueToSessionLock(mode, pid))
    {
        return;
    }
    
    int lastMode = g_lastMode.load();
    DWORD lastPid = g_lastPid.load();
    
    // Check cooldown
    if (!IsPolicyChangeAllowed(mode)) return;
    
    // 1. Exact same process and mode - skip entirely
    if (mode == lastMode && pid == lastPid)
    {
        return;
    }

    static std::unordered_set<DWORD> loggedActivePids;
    static std::mutex loggedActivePidsMtx;

    {
        std::lock_guard<std::mutex> lg(loggedActivePidsMtx);
        if (!loggedActivePids.insert(pid).second)
        {
            return;
        }
    }
    
    // 2. Track if this is a mode change or just PID change (launcher->game)
    bool modeChanged = (mode != lastMode);
    bool pidChanged = (pid != lastPid);
    
    if (pidChanged && mode == lastMode)
    {
        Log("Process transition: " + std::to_string(lastPid) + " -> " + std::to_string(pid) + 
            " (Same mode - applying process-specific optimizations only)");
        
        g_lastPid.store(pid);
        
        if (mode == 1 && g_sessionLocked.load())
        {
            g_lockedGamePid.store(pid);
            
            // Update process identity for the lock
            ProcessIdentity newIdentity;
            if (GetProcessIdentity(pid, newIdentity))
            {
                std::lock_guard lock(g_processIdentityMtx);
                g_lockedProcessIdentity = newIdentity;
            }
        }
        
        // DO NOT RETURN - Continue to apply process-specific optimizations
    }
    
    DWORD val = (mode == 1) ? VAL_GAME : VAL_BROWSER;
    
    // Pre-game RAM cleaning
    if (mode == 1)
    {
        static std::unordered_set<DWORD> cleanedGamePids;
        DWORD lastClean = g_lastRamCleanPid.load();
        if (lastClean != pid)
        {
            if (IsUnderMemoryPressure())
            {
                Log("[RAM] Memory pressure detected - performing pre-game cleanup");
                IntelligentRamClean();
            }
            else
            {
                Log("[RAM] Memory OK - skipping cleanup");
            }

            cleanedGamePids.insert(pid);
            g_lastRamCleanPid.store(pid);
        }
    }

    bool changeSuccess = false;

    // Apply GLOBAL registry settings only if mode actually changed
    if (modeChanged && g_caps.hasAdminRights)
    {
        if (SetPrioritySeparation(val))
        {
            changeSuccess = true;
        }
        
        // Apply other global settings
        SetNetworkQoS(mode);
        SetMemoryCompression(mode);
        SetTimerResolution(mode);
        SetTimerCoalescingControl(mode);
    }
    else if (modeChanged)
    {
        Log("[READ-ONLY] Detected " + exe + " -> Would set " + 
            (mode == 1 ? "GAME" : "BROWSER") + " mode, but missing Admin rights.");
        changeSuccess = true; 
    }
    else
    {
        // Same mode, different PID - skip global settings
        changeSuccess = true;
    }

    if (changeSuccess)
    {
        // Update tracking (always)
        if (modeChanged)
        {
            g_lastMode.store(mode);
        }
        g_lastPid.store(pid);
        
        // Store process identity for PID reuse protection
        ProcessIdentity newIdentity;
        if (GetProcessIdentity(pid, newIdentity)) {
            std::lock_guard lock(g_processIdentityMtx);
            g_lockedProcessIdentity = newIdentity;
        }
        
        if (modeChanged)
        {
            Log((mode == 1 ? "[GAME] "s : "[BROWSER] "s) + exe);
        }
        
        // Apply PROCESS-SPECIFIC optimizations (ALWAYS for new PID)
        if (g_cpuInfo.vendor == CPUVendor::Intel && g_caps.hasHybridCores)
        {
            SetHybridCoreAffinity(pid, mode);
        }
        else if (g_cpuInfo.vendor == CPUVendor::AMD && g_cpuInfo.hasAmd3DVCache)
        {
            SetAmd3DVCacheAffinity(pid, mode);
        }
        
        SetProcessIoPriority(pid, mode);
        SetGpuPriority(pid, mode);
        SetProcessAffinity(pid, mode);
        SetWorkingSetLimits(pid, mode);
        OptimizeDpcIsrLatency(pid, mode);
        
        // Update policy change timestamp
        if (modeChanged)
        {
            g_lastPolicyChange.store(std::chrono::steady_clock::now().time_since_epoch().count());
        }
    
        // Session lock management (only for mode changes)
        if (mode == 1 && modeChanged)
        {
            g_sessionLocked.store(true);
            g_lockedGamePid.store(pid);
            g_lockStartTime.store(std::chrono::steady_clock::now().time_since_epoch().count());
    
            // Store process identity for PID reuse protection
            ProcessIdentity currentIdentity;
            if (GetProcessIdentity(pid, currentIdentity)) {
                std::lock_guard lock(g_processIdentityMtx);
                g_lastProcessIdentity = currentIdentity;
            }
    
            Log("Session lock ACTIVATED - game mode locked (PID: " + std::to_string(pid) + ")");

            if (g_suspendUpdatesDuringGames.load())
            {
                SuspendBackgroundServices();
            }
            else
            {
                Log("[SERVICE] Service suspension disabled by config");
            }
        }
        else
        {
            if (g_sessionLocked.load())
            {
                g_sessionLocked.store(false);
                g_lockedGamePid.store(0);
                g_lockStartTime.store(0);
                Log("Session lock RELEASED - switched to browser mode");

                if (g_suspendUpdatesDuringGames.load())
                {
                    Log("[SERVICE] About to resume background services...");
                    ResumeBackgroundServices();
                    Log("[SERVICE] Background services resume call completed");
                }
                else
                {
                    Log("[SERVICE] Resume skipped (suspension disabled by config)");
                }
            }
        }
    }
}