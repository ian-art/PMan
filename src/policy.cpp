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
    
    std::wstring titleStr = title;
    std::wstring classStr = className;
    
    // Convert to lowercase once (optimization)
    asciiLower(titleStr);
    asciiLower(classStr);
    
    std::shared_lock lg(g_setMtx);
    
	// Fix Use direct find() since strings are already lowercased (avoids allocs)
    for (const auto& pattern : g_gameWindows)
    {
        if (titleStr.find(pattern) != std::wstring::npos || 
            classStr.find(pattern) != std::wstring::npos)
        {
            return 1;
        }
    }
    
    // Check browser windows
    for (const auto& pattern : g_browserWindows)
    {
        if (titleStr.find(pattern) != std::wstring::npos || 
            classStr.find(pattern) != std::wstring::npos)
        {
            return 2;
        }
    }
    
    return 0;
}

void CheckAndReleaseSessionLock()
{
    if (!g_sessionLocked.load()) return;
    
    // Double-checked locking pattern with memory barriers
    ProcessIdentity lockedIdentity;
    {
        std::lock_guard lock(g_processIdentityMtx);
        if (!g_sessionLocked.load(std::memory_order_acquire)) return;
        lockedIdentity = g_lockedProcessIdentity;
    }

    // Check if process still exists (expensive operation, outside lock)
    if (!IsProcessIdentityValid(lockedIdentity))
    {
        {
            std::lock_guard lock(g_processIdentityMtx);
            // Re-check under lock to prevent TOCTOU race
            if (!g_sessionLocked.load(std::memory_order_acquire)) return;
            if (!(g_lockedProcessIdentity == lockedIdentity)) return;
            
            DWORD lockedPid = lockedIdentity.pid;
            Log("Session lock RELEASED - process " + std::to_string(lockedPid) + " no longer exists");
            
            // Notify Performance Guardian
            g_perfGuardian.OnGameStop(lockedPid);
            
            // ---------------------------------------------------------
            // CRITICAL FIX: Trigger Post-Game Boost immediately
            // Since the game is gone, we must restore the Desktop UI now.
            // ---------------------------------------------------------
            g_explorerBooster.OnGameStop(); 
            // ---------------------------------------------------------

            // Use memory barriers for atomic consistency
            g_lockedGamePid.store(0, std::memory_order_release);
            g_sessionLocked.store(false, std::memory_order_release);
            
            g_lastProcessIdentity = {0, {0, 0}};
            g_lockedProcessIdentity = {0, {0, 0}};
        }
        
        // Lock released by scope exit before potentially blocking operation
        ResumeBackgroundServices();
    }
}

bool ShouldIgnoreDueToSessionLock(int detectedMode, DWORD pid)
{
    if (!g_sessionLocked.load()) return false;
    
    // CRITICAL FIX: Hierarchy check must be global, NOT nested inside browser check
    // Allow children of the locked game to pass through regardless of detected mode
    {
        std::shared_lock lh(g_hierarchyMtx);
        if (g_inheritedGamePids.count(pid)) {
            return false; // Inherit parent's lock permission
        }
    }

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
            // Fix: Validate window handle to prevent null pointer dereference
            if (fg) GetWindowThreadProcessId(fg, &fgPid);

            // Fix Verify PID Identity to prevent PID reuse exploits
            if (fgPid == lockedIdentity.pid)
            {
                ProcessIdentity fgIdentity;
                if (GetProcessIdentity(fgPid, fgIdentity) && fgIdentity == lockedIdentity)
                {
                    Log("Session lock ACTIVE - ignoring browser switch (locked to game PID: " +
                        std::to_string(lockedIdentity.pid) + ")");
                    return true;
                }
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
    auto nowPoint = std::chrono::steady_clock::now();
    auto lastChangeRep = g_lastPolicyChange.load();
    
    if (lastChangeRep == 0) return true;

    // Fix Use portable chrono math instead of hardcoded division
    auto lastPoint = std::chrono::steady_clock::time_point(std::chrono::steady_clock::duration(lastChangeRep));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(nowPoint - lastPoint).count();
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
    
	// Fix Validate window handle before use if provided
    if (hwnd && !IsWindow(hwnd)) hwnd = nullptr;

    CheckAndReleaseSessionLock();
    
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
    {
#ifdef _DEBUG
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            Log("[DEBUG] [POLICY] OpenProcess Access Denied for PID " + std::to_string(pid));
#endif
        return;
    }
    
	// Fix Support paths longer than MAX_PATH (260 chars)
    DWORD sz = MAX_PATH;
    std::vector<wchar_t> pathBuf(sz);
    BOOL success = QueryFullProcessImageNameW(h, 0, pathBuf.data(), &sz);
    
	if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pathBuf.resize(sz + 1); // Resize to required length + null terminator
        success = QueryFullProcessImageNameW(h, 0, pathBuf.data(), &sz);
    }

	DWORD err = GetLastError();
    // Fix: Keep handle open (RAII) to prevent PID reuse during evaluation
    UniqueHandle hGuard(h); 
    
    if (!success)
    {
        // Fix: Suppress log noise for short-lived processes (Race Condition)
        // ERROR_GEN_FAILURE (31) = Device not functioning (common for zombies)
        // ERROR_ACCESS_DENIED (5) = Protected process (e.g. anti-cheat/system)
        // ERROR_INVALID_PARAMETER (87) = Process handle bad/exiting
        if (err != ERROR_GEN_FAILURE && err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_PARAMETER && err != ERROR_PARTIAL_COPY)
        {
            Log("[POLICY] QueryFullProcessImageNameW failed for PID " + std::to_string(pid) + 
                ": " + std::to_string(err));
        }
        return;
    }

	// Fix: Re-verify PID identity to prevent acting on recycled PID
    ProcessIdentity verifyIdentity;
    if (!GetProcessIdentity(pid, verifyIdentity)) return;
    
	// Fix: Use pathBuf.data() because 'path' was replaced by a vector
    std::wstring exe = ExeFromPath(pathBuf.data());
	if (exe.empty()) return;

    // FIX: Normalize to lowercase for consistent lookups (Ignore List, Games, Browsers)
    asciiLower(exe);

    int mode = 0; // FIX: Declare mode early so it can be used by goto logic
    bool isLauncher = false; // FIX: Declare variable early to avoid C2362 error with goto
	
    // ---------------------------------------------------------
    // IGNORE: Windows Shell Experience Hosts
    // These system processes often match generic "Browser" window patterns 
    // (e.g., WebView/AppFrame) but should NEVER trigger a mode switch 
    // or disable Explorer boosts. They are part of the "Desktop" experience.
    // ---------------------------------------------------------
    static const std::unordered_set<std::wstring> SHELL_PROCESSES = {
        L"searchhost.exe",
        L"startmenuexperiencehost.exe",
        L"shellexperiencehost.exe",
        L"applicationframehost.exe",
        L"systemsettings.exe",
        L"lockapp.exe",
        L"textinputhost.exe",
        L"ctfmon.exe",
        L"smartscreen.exe",
        L"taskmgr.exe"
    };
    
	// Check global ignore list
    // FIX: If ignored, force Desktop Mode (0) and skip detection, 
    // but proceed to Apply Policy so we can release locks.
    {
        std::shared_lock lg(g_setMtx);
        if (g_ignoredProcesses.count(exe)) {
            mode = 0;
            goto apply_policy;
        }
    }

	// TIER 3 CHECK: Game Launchers (Moved to top to prevent early exit)
    isLauncher = GAME_LAUNCHERS.count(exe);
    if (!isLauncher)
    {
        std::shared_lock lg(g_setMtx);
        isLauncher = g_customLaunchers.count(exe);
    }

    if (isLauncher) 
    {
        Log("[TIER3] Launcher detected: " + WideToUtf8(exe.c_str()));
        
        // Open with PROCESS_SET_QUOTA for working set limits
        HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid);
        if (hProc) {
            // 1. Deprioritize CPU Priority
            SetPriorityClass(hProc, IDLE_PRIORITY_CLASS); // Never preempt game
            
            // 2. Deprioritize I/O (Using existing helper which takes PID and Mode 2=Low)
            SetProcessIoPriority(pid, 2);   

            // 3. Pin to Core 0 only (Efficiency Core on Intel, or weakest thread)
            SetProcessAffinityMask(hProc, 1);             
            
            // 4. Aggressive Memory Trimming
            // Special case: Don't freeze anti-cheat services if they mistakenly ended up in this list
            if (exe != L"riot-vanguard.exe" && exe != L"easyanticheat.exe" && 
                exe != L"beservice.exe" && exe != L"navapsvc.exe") 
            {
                // Aggressive trim to 50MB-100MB
                SetProcessWorkingSetSize(hProc, 50 * 1024 * 1024, 100 * 1024 * 1024); 
            }
            
            CloseHandle(hProc);
        }
        return; // Skip standard game/browser logic
    }

    if (hwnd)
    {
        mode = DetectWindowType(hwnd);
        if (mode != 0)
        {
            Log("Window detection: " + WideToUtf8(exe.c_str()) + " detected via window " + 
                (mode == 1 ? "(GAME)" : "(BROWSER)"));
        }
    }
    
	if (mode == 0)
    {
        std::shared_lock lg(g_setMtx);
        if (g_games.count(exe))   mode = 1;
        else if (g_browsers.count(exe)) mode = 2;
    }

    // Hierarchy Inheritance Override
    if (mode == 0) 
    {
        std::shared_lock lh(g_hierarchyMtx);
        if (g_inheritedGamePids.count(pid)) 
        {
             mode = 1;
        }
    }
    
apply_policy: // FIX: Label for the goto jump
    // FIX: Allow transition to Desktop (Mode 0) to release locks.
    // We only return if we are ALREADY in desktop mode.
    if (mode == 0)
    {
        // If we were previously in Game/Browser mode (lastMode != 0), 
        // we MUST proceed to call OnGameStop().
        if (!hwnd || g_lastMode.load() == 0) return;
    }
    
    if (ShouldIgnoreDueToSessionLock(mode, pid))
    {
        return;
    }
    
    int lastMode = g_lastMode.load();
	DWORD lastPid = g_lastPid.load();
    
    // CRITICAL: Revert Explorer BEFORE game mode applies to prevent conflict
    if (mode == 1) {
        // Pre-emptive revert
        g_explorerBooster.OnGameStart(pid);
    } else if (mode == 2) {
        g_explorerBooster.OnBrowserStart(pid);
    }
    
    // Check cooldown
    if (!IsPolicyChangeAllowed(mode)) return;
    if (!IsPolicyChangeAllowed(mode)) return;
    
    // 1. Exact same process and mode - skip entirely
    if (mode == lastMode && pid == lastPid)
    {
        return;
    }

    // Fix: Removed static locals to prevent hidden state issues.
    // Relying on g_lastPid check (above) which handles the majority of spam.
    
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
            // Transition profiling to new PID (Stop old launcher, start new game)
            g_perfGuardian.OnGameStop(g_lockedGamePid.load());
            g_perfGuardian.OnGameStart(pid, exe);

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
        // Fix: Removed leaking static set. Rely on atomic tracker.
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
        Log("[READ-ONLY] Detected " + WideToUtf8(exe.c_str()) + " -> Would set " + 
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
        // Fix Atomic update of both PID and Mode
        uint64_t encodedState = (static_cast<uint64_t>(pid) << 32) | static_cast<uint32_t>(mode);
        g_policyState.store(encodedState, std::memory_order_release);

		if (modeChanged)
        {
            g_lastMode.store(mode, std::memory_order_release);
        }
        g_lastPid.store(pid, std::memory_order_release);
        
        // Store process identity for PID reuse protection
        ProcessIdentity newIdentity;
        if (GetProcessIdentity(pid, newIdentity)) {
            std::lock_guard lock(g_processIdentityMtx);
            g_lockedProcessIdentity = newIdentity;
        }

        // TIER 2 CHECK: Anti-Cheat & Workers
        bool isGameChild = false;
        if (mode == 1) 
        {
            if (IsAntiCheatProtected(pid)) 
            {
                Log("[TIER2] Anti-cheat protection detected - applying worker isolation");
                isGameChild = true;
            }
            else 
            {
                // Check hierarchy for inherited status
                std::shared_lock lh(g_hierarchyMtx);
                if (g_inheritedGamePids.count(pid)) {
                    isGameChild = true;
                }
            }
        }

        if (modeChanged)
        {
            Log((mode == 1 ? "[GAME] "s : "[BROWSER] "s) + WideToUtf8(exe.c_str()));
        }
        
        // Apply TIERED Optimizations (CPU/IO Isolation)
        if (mode == 1) 
        {
            ApplyTieredOptimization(pid, mode, isGameChild);
            
            // Apply supplementary optimizations
            if (!isGameChild) {
                SetGpuPriority(pid, mode); // Only Tier 1 gets GPU priority
                SetProcessAffinity(pid, mode); // Standard affinity fallback
                SetWorkingSetLimits(pid, mode);
                OptimizeDpcIsrLatency(pid, mode);
            } else {
                // Tier 2 gets standard affinity fallback but no GPU boost
                 SetProcessAffinity(pid, mode);
            }
            
            // Special handling for AMD 3D V-Cache (Tier 1 Only)
            if (!isGameChild && g_cpuInfo.vendor == CPUVendor::AMD && g_cpuInfo.hasAmd3DVCache)
            {
                SetAmd3DVCacheAffinity(pid, mode);
            }
        }
        else 
        {
            // Browser / Normal Mode
            SetHybridCoreAffinity(pid, mode);
            SetProcessIoPriority(pid, mode);
            SetProcessAffinity(pid, mode);
            SetWorkingSetLimits(pid, mode);
            OptimizeDpcIsrLatency(pid, mode);
        }
        
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

            // Initialize Performance Guardian Session
            g_perfGuardian.OnGameStart(pid, exe);
    
            // Verify if core pinning is allowed by profile
            if (!g_perfGuardian.IsOptimizationAllowed(exe, "pin")) {
                Log("[PERF] Core pinning disabled by learned profile for " + WideToUtf8(exe.c_str()));
                // Revert affinity to all cores if it was set
                SetProcessAffinity(pid, 2); 
            }	
	
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
            // CRITICAL FIX: Only stop/boost explorer if we are returning to DESKTOP (0).
            // If we are switching to Browser Mode (2), OnBrowserStart() was already called,
            // so we must NOT call OnGameStop() (which would disable the active flag).
            if (mode == 0) {
                 g_explorerBooster.OnGameStop();
            }

            // CRITICAL FIX: ALWAYS call OnGameStop when leaving game mode
            // This resets m_gameOrBrowserActive flag
            // (Wait, the comment above says "only if returning to desktop", but check logic:)
            // If mode == 2, OnBrowserStart set Active=true. If we call OnGameStop here, it sets Active=false.
            // So limiting OnGameStop to (mode == 0) is the CORRECT fix.

            if (g_sessionLocked.load())
            {
                // Notify Performance Guardian and generate report
                DWORD stoppingPid = g_lockedGamePid.load();
                if (stoppingPid != 0) g_perfGuardian.OnGameStop(stoppingPid);

                g_sessionLocked.store(false);
                g_lockedGamePid.store(0);
                g_lockStartTime.store(0);
                Log("Session lock RELEASED - switched to browser/desktop mode");

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