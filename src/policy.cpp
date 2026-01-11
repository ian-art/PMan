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

#include "policy.h"
#include "throttle_manager.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "tweaks.h"
#include "services.h"
#include "sysinfo.h"
#include <wtsapi32.h>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <thread>

// ============================================
// POLICY WORKER QUEUE INFRASTRUCTURE
// ============================================
struct PolicyJob { 
    DWORD pid; 
    HWND hwnd; 
};

static std::vector<PolicyJob> g_policyQueue;
static std::mutex g_policyQueueMtx;
static std::condition_variable g_policyCv;
static std::atomic<bool> g_workerRunning{false};

// Background Activity Classification
ProcessNetClass ClassifyProcessActivity(DWORD pid, const std::wstring& exeName) {
    // 1. Safety Check: System Critical (Uses centralized utils check)
    if (IsSystemCriticalProcess(exeName)) return ProcessNetClass::SystemCritical;

    // 2. User Config: User Critical (Games/Players/Browsers)
    {
        std::shared_lock lg(g_setMtx);
        if (g_games.count(exeName) || g_videoPlayers.count(exeName) || g_browsers.count(exeName)) {
            return ProcessNetClass::UserCritical;
        }
    }

    // 3. Network Behavior Check
    bool isNetActive = false;
    {
        std::shared_lock lock(g_netActivityMtx);
        isNetActive = g_activeNetPids.count(pid);
    }

    if (isNetActive) {
        // Known Background Hogs
        if (exeName == L"dosvc.exe" || exeName == L"gamingservices.exe" || 
            exeName == L"clicktorunsvc.exe" || exeName == L"onedrive.exe" || 
            exeName == L"backgroundtaskhost.exe") 
        {
            return ProcessNetClass::NetworkBound; // Valid target for throttling
        }
        
        // Launchers in background (when game is running) are also Network Bound
        // Note: GAME_LAUNCHERS is defined in constants.h, we can access it here
        {
            std::shared_lock lg(g_setMtx);
            // Check if it's a custom launcher or a known standard launcher
            if (g_customLaunchers.count(exeName)) {
                return ProcessNetClass::NetworkBound;
            }
        }
        // Iterate standard list (defined in constants.h, available via globals or direct check)
        // Since GAME_LAUNCHERS is in constants.h which policy.cpp includes indirectly via globals->constants
        if (GAME_LAUNCHERS.count(exeName)) {
            return ProcessNetClass::NetworkBound;
        }
    }

    // 4. Default
    return ProcessNetClass::Unknown;
}

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
    if (!IsProcessIdentityValid(currentIdentity))
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
    // [POLISH] Reduced to 5s to improve Alt-Tab responsiveness while preventing thrashing
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

// ============================================
// POLICY WORKER THREAD (Extracted Logic)
// ============================================
static void PolicyWorkerThread(DWORD pid, HWND hwnd)
{
    try {
        // Re-verify flags inside thread
        if (!g_running || g_userPaused.load()) return;

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
        
        HANDLE hRaw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hRaw)
        {
#ifdef _DEBUG
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED)
                Log("[DEBUG] [POLICY] OpenProcess Access Denied for PID " + std::to_string(pid));
#endif
            return;
        }
        // FIX: Wrap handle immediately to prevent leak if vector allocation throws
        UniqueHandle hGuard(hRaw);
        
        // Fix Support paths longer than MAX_PATH (260 chars)
        DWORD sz = MAX_PATH;
        std::vector<wchar_t> pathBuf(sz);
        BOOL success = QueryFullProcessImageNameW(hGuard.get(), 0, pathBuf.data(), &sz);
        
        if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pathBuf.resize(sz + 1); // Resize to required length + null terminator
            success = QueryFullProcessImageNameW(hGuard.get(), 0, pathBuf.data(), &sz);
        }

        DWORD err = GetLastError();
        
        if (!success)
        {
            // Fix: Suppress log noise for short-lived processes
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

        // Network Policy Enrollment
        // Check if this is a background bandwidth hog BEFORE applying game/desktop logic
        ProcessNetClass netClass = ClassifyProcessActivity(pid, exe);
        if (netClass == ProcessNetClass::NetworkBound) {
            // Throttling (Job Object + Dynamic Priority)
            g_throttleManager.ManageProcess(pid);
            // We continue execution so standard optimizations can still apply if needed,
            // but typically NetworkBound apps are background services.
        }

        int mode = 0; // FIX: Declare mode early so it can be used by goto logic
        bool forceOverride = false;
        bool isLauncher = false; // FIX: Declare variable early to avoid C2362 error with goto

        // ---------------------------------------------------------
        // STEP 1: CHECK IGNORE LIST (Highest Priority)
        // ---------------------------------------------------------
        // If ignored, force Desktop Mode (0) and skip all detection.
        {
            std::shared_lock lg(g_setMtx);
            if (!g_ignoredProcesses.count(exe)) {
                
                // SPECIAL CASE: Force Game Mode for Old/DX9 Games
                // These games often have "Launcher" in their window title or lack standard game windows
                if (g_oldGames.count(exe)) {
                    mode = 1; 
                    forceOverride = true;
                    Log("Force-enabling GAME mode for Legacy/DX9 title: " + WideToUtf8(exe.c_str()));
                    // Jump to policy application to skip generic heuristics
                    goto apply_policy;
                }
                mode = DetectWindowType(hwnd);
            }
        }

        // ---------------------------------------------------------
        // STEP 2: CHECK LAUNCHERS (Tier 3)
        // ---------------------------------------------------------
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
                SetPriorityClass(hProc, IDLE_PRIORITY_CLASS);  // Never preempt game
                // 2. Deprioritize I/O (Using existing helper which takes PID and Mode 2=Low)
                SetProcessIoPriority(pid, 2);   
                // 3. Pin to all cores EXCEPT Core 0 (Leave Core 0 for OS/critical tasks)
                // FIX: Core 0 is often the most contended. Pining heavy launchers here causes lag.
                SetProcessAffinityMask(hProc, g_physicalCoreMask & ~0x1);             
                
                // 4. Moderate Memory Trimming
                // Special case: Don't freeze anti-cheat services if they mistakenly ended up in this list
                if (!IsAntiCheatProcess(exe)) 
                {
                    // FIX: Moderate trim to 200MB-500MB to prevent UI hangs/crashes
                    SetProcessWorkingSetSize(hProc, 200 * 1024 * 1024, 500 * 1024 * 1024); 
                }
                CloseHandle(hProc);
            }
            return; // Skip standard logic
        }

        // ---------------------------------------------------------
        // STEP 3: CHECK HIERARCHY INHERITANCE (Optimization)
        // ---------------------------------------------------------
        // Check if this process is a child of a known game. 
        // If so, set Game Mode (1) immediately and skip expensive window detection.
        {
            std::shared_lock lh(g_hierarchyMtx);
            if (g_inheritedGamePids.count(pid)) 
            {
                 mode = 1;
            }
        }

        // ---------------------------------------------------------
        // STEP 4: WINDOW DETECTION (Only if mode not yet determined)
        // ---------------------------------------------------------
        // Skip window detection for processes we know should be ignored
        // This prevents cmd.exe/explorer.exe windows from being misclassified
        if (mode == 0 && hwnd)
        {
            // Double-check: if exe is in ignore list, skip window detection entirely
            {
                std::shared_lock lg(g_setMtx);
                if (!g_ignoredProcesses.count(exe)) {
                    mode = DetectWindowType(hwnd);
                    if (mode != 0)
                    {
                        Log("Window detection: " + WideToUtf8(exe.c_str()) + " detected via window " + 
                            (mode == 1 ? "(GAME)" : "(BROWSER)"));
                    }
                }
            }
        }
        
        // ---------------------------------------------------------
        // STEP 5: NAME LIST DETECTION (Only if mode not yet determined)
        // ---------------------------------------------------------
        if (mode == 0)
        {
            std::shared_lock lg(g_setMtx);
            if (g_games.count(exe))   mode = 1;
            else if (g_videoPlayers.count(exe)) mode = 1; // Treat Video Players as Games (High Perf)
            else if (g_browsers.count(exe)) mode = 2;
        }

    apply_policy:  // FIX: Label for the goto jump
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
        
        // Fix: Atomic snapshot of policy state to prevent torn reads
        uint64_t state = g_policyState.load();
        DWORD lastPid = static_cast<DWORD>(state >> 32);
        int lastMode = static_cast<int>(state & 0xFFFFFFFF);

        // FIX: Check cooldown BEFORE modifying ExplorerBooster state to prevent desync
        if (!forceOverride && !IsPolicyChangeAllowed(mode)) return;
        
        // CRITICAL: Revert Explorer BEFORE game mode applies to prevent conflict
        if (mode == 1) {
            // Pre-emptive revert
            g_explorerBooster.OnGameStart(pid);
        } else if (mode == 2) {
            g_explorerBooster.OnBrowserStart(pid);
        }
        
        // 1. Exact same process and mode - skip entirely
        if (mode == lastMode && pid == lastPid)
        {
            return;
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
                std::string prefix = "[BROWSER] ";
                if (mode == 1) {
                    // Distinguish Game vs Video for logging
                    bool isVideo = false;
                    { std::shared_lock lg(g_setMtx); isVideo = g_videoPlayers.count(exe); }
                    prefix = isVideo ? "[VIDEO] " : "[GAME] ";
                }
                Log(prefix + WideToUtf8(exe.c_str()));
            }
            
            // --- CPU Affinity Strategy ---
            AffinityStrategy strategy = GetRecommendedStrategy();

            if (strategy == AffinityStrategy::HybridPinning) 
            {
                // Intel 12th+ Gen: Use P-Cores for Game, E-Cores for Background
                SetHybridCoreAffinity(pid, mode);
            } 
            else if (strategy == AffinityStrategy::GameIsolation) 
            {
                // Homogeneous (Old Intel/AMD): Use Core Partitioning
                SetProcessAffinity(pid, mode);
            }
            // else: Strategy::None -> Do nothing

            // Apply TIERED Optimizations (CPU/IO Isolation)
            if (mode == 1) 
            {
                ApplyTieredOptimization(pid, mode, isGameChild);
                
                // Apply supplementary optimizations
                if (!isGameChild) {
                    SetGpuPriority(pid, mode); 
                    SetWorkingSetLimits(pid, mode);
                    OptimizeDpcIsrLatency(pid, mode);
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
                // FIX: Do not apply browser optimizations (Low I/O) to Desktop/Explorer (Mode 0)
                if (mode != 0)
                {
                    // Apply strategy-based affinity
                    
                    if (strategy == AffinityStrategy::HybridPinning) 
                    {
                        SetHybridCoreAffinity(pid, mode);
                    } 
                    else if (strategy == AffinityStrategy::GameIsolation) 
                    {
                        SetProcessAffinity(pid, mode);
                    }
                    
                    SetProcessIoPriority(pid, mode);
                    SetWorkingSetLimits(pid, mode);
                    OptimizeDpcIsrLatency(pid, mode);
                }
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
                if (mode == 0) {
                     g_explorerBooster.OnGameStop();
                }

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
        
    } catch (const std::exception& e) {
        Log("[POLICY] Exception in policy thread: " + std::string(e.what()));
    } catch (...) {
        Log("[POLICY] Unknown exception in policy thread");
    }
}

// ============================================
// MAIN POLICY ENTRY POINT (Queue-Based)
// ============================================
void EvaluateAndSetPolicy(DWORD pid, HWND hwnd)
{
    if (!g_running || pid == 0 || pid == GetCurrentProcessId()) return;
    if (g_userPaused.load()) return;

    // Lazy-initialize single worker thread
    static std::once_flag workerFlag;
    std::call_once(workerFlag, []() {
        g_workerRunning = true;
        std::thread([]() {
            while (g_running) {
                PolicyJob job = {0, 0};
                {
                    std::unique_lock<std::mutex> lock(g_policyQueueMtx);
                    g_policyCv.wait(lock, []{ 
                        return !g_policyQueue.empty() || !g_running; 
                    });
                    if (!g_running) break;
                    job = g_policyQueue.front();
                    g_policyQueue.erase(g_policyQueue.begin());
                }
                // Process job with extracted logic
                PolicyWorkerThread(job.pid, job.hwnd);
            }
        }).detach();
    });

    // Enqueue job for worker thread
    {
        std::lock_guard<std::mutex> lock(g_policyQueueMtx);
        g_policyQueue.push_back({pid, hwnd});
    }
    g_policyCv.notify_one();
}