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

#include "sandbox_executor.h"
#include "logger.h"
#include "context.h"
#include "utils.h" // For ExeFromPath
#include "memory_optimizer.h"
#include "globals.h"
#include "services.h" // Required for Service Suspension
#include "tweaks.h" // Required for SetProcessIoPriority
#include "nt_wrapper.h"
#include <psapi.h>

// [DEFINITIONS] Power Throttling (EcoQoS)
#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#define ProcessPowerThrottling (static_cast<PROCESS_INFORMATION_CLASS>(4))
typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE, *PPROCESS_POWER_THROTTLING_STATE;
#endif

// UpdateLeaseLedger logic moved to Shared Utils (UpdateSessionLedger)

// [SECURITY PATCH] Immutable Core List ("Trusted Assassin" Mitigation)
// [IMPORT] Re-use the robust heuristic from services.cpp (Move to utils or duplicate here)
[[maybe_unused]] static bool IsProtectedProcess_Local(DWORD pid) {
    UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProcess) return (GetLastError() == ERROR_ACCESS_DENIED); // Access Denied = Likely Protected
    
    PROCESS_PROTECTION_LEVEL_INFORMATION ppl = {0};
    if (GetProcessInformation(hProcess.get(), (PROCESS_INFORMATION_CLASS)11, &ppl, sizeof(ppl))) {
        return (ppl.ProtectionLevel != 0);
    }
    return false;
}

static bool IsImmutableSystemProcess(HANDLE hProc) {
    // [SECURITY FIX] Handle-Based Verification (Prevents TOCTOU)
    if (!hProc) return true; // Fail safe

    // Check Protection Level on the ACTIVE handle
    PROCESS_PROTECTION_LEVEL_INFORMATION ppl = {0};
    if (GetProcessInformation(hProc, (PROCESS_INFORMATION_CLASS)11, &ppl, sizeof(ppl))) {
        if (ppl.ProtectionLevel != 0) return true;
    }

    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
        std::wstring fullPath = path;
        std::wstring name = ExeFromPath(path);
        
        // Normalize
        for (auto& c : name) c = towlower(c);
        for (auto& c : fullPath) c = towlower(c);

        // [SECURITY FIX] Path Validation
        // Critical system processes MUST reside in C:\Windows\System32 (or equivalent)
        // This prevents "C:\Temp\csrss.exe" masquerade attacks.
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring sysDirStr = sysDir;
        for (auto& c : sysDirStr) c = towlower(c);

        bool isSystemLoc = (fullPath.find(sysDirStr) != std::wstring::npos);

        // The "Do Not Touch" List
        if (name == L"msmpeng.exe" ||  // Windows Defender
            (isSystemLoc && name == L"csrss.exe") ||    // Client Server Runtime (Strict Path)
            (isSystemLoc && name == L"smss.exe") ||     // Session Manager (Strict Path)
            name == L"services.exe" || // SCM
            name == L"lsass.exe" ||    // Local Security Authority
            name == L"wininit.exe" ||  // Windows Init
            name == L"winlogon.exe") { // Logon
            return true;
        }
    }
    return false;
}

SandboxResult SandboxExecutor::TryExecute(ArbiterDecision& decision) {
    SandboxResult result = { false, false, false, "None", 0 };

    // [FAULT INJECTION]
    if (PManContext::Get().fault.sandboxError) {
        result.executed = false;
        result.reversible = false;
        result.committed = false;
        result.reason = "Fault:ExecutionError";
        decision.isReversible = false;
        Log("[FAULT] SandboxExecutor: Execution Error Simulated.");
        return result; 
    }

    // [PASSIVE MODE GUARD]
    // If Passive Mode is active (Pause Idle), strictly forbid affinity/topology changes.
    // We only allow Priority changes (Throttle_Mild) or Maintain.
    if (PManContext::Get().conf.pauseIdle) {
        bool isAllowedInPassive = (decision.selectedAction == BrainAction::Maintain || 
                                   decision.selectedAction == BrainAction::Throttle_Mild);
        
        if (!isAllowedInPassive) {
            result.executed = false;
            result.reversible = true; // Can retry later
            result.committed = false;
            result.reason = "PassiveModeRestricted";
            decision.isReversible = false;
            return result;
        }
    }

    // 0. Lease Management: Automatic Reversion (Voluntary)
    // If the Arbiter requests Maintain, we must release any active lease immediately.
    if (decision.selectedAction == BrainAction::Maintain) {
        if (m_actionApplied) {
            Rollback(); // Revert to baseline (Triggers Cooldown)
            
            result.executed = false;
            result.reversible = true;
            result.committed = false;
            result.reason = "LeaseReleased"; // Explicit release
            decision.isReversible = true;
            return result;
        }

        // Standard Maintain
        result.executed = false;
        result.reversible = true;
        result.committed = true;
        result.reason = "NoAction";
        decision.isReversible = true;
        return result;
    }

    // 1. Strict Allowlist (Reversibility Check)
    if (decision.selectedAction != BrainAction::Throttle_Mild && 
        decision.selectedAction != BrainAction::Shield_Foreground &&
        decision.selectedAction != BrainAction::Boost_Process && // [FIX] Allow Boost
        decision.selectedAction != BrainAction::Suspend_Services && 
        decision.selectedAction != BrainAction::Release_Pressure &&
        decision.selectedAction != BrainAction::Action_MemoryHarden &&
        decision.selectedAction != BrainAction::Action_MemoryTrim) {
        result.executed = false;
        result.reversible = false; // Strictly forbidden
        result.committed = false;
        result.reason = "Rejected";
        decision.isReversible = false;
        return result;
    }

    // 2. Lease Management: Expiry Check (Time-Bound)
    // If we are already holding the state, check if the lease has expired.
    if (m_actionApplied) {
        uint64_t now = GetTickCount64();
        if ((now - m_leaseStart) > MAX_LEASE_MS) {
            Rollback(); // Force Revert (Triggers Cooldown)
            
            result.executed = false;
            result.reversible = true;
            result.committed = false;
            result.reason = "LeaseExpired";
            decision.isReversible = false; // Deny to force a cooldown/re-eval
            return result;
        }

        // Lease Valid: Renew
        result.executed = true;
        result.reversible = true;
        result.committed = true;
        result.reason = "LeaseRenewed";
        decision.isReversible = true;
        return result;
    }

    // 3. Cooldown Enforcement (Rate-of-Change Limiter)
    // If we are NOT holding state, we must check if we are in a cooldown period.
    uint64_t now = GetTickCount64();
    if (!m_actionApplied && (now - m_lastReleaseTime < COOLDOWN_MS)) {
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "CooldownActive";
        result.cooldownRemaining = COOLDOWN_MS - (now - m_lastReleaseTime);
        decision.isReversible = false; // Deny authority
        return result;
    }

    // 3. Target Selection
    DWORD targetPid = decision.targetPid != 0 ? decision.targetPid : GetCurrentProcessId();
    if (decision.selectedAction == BrainAction::Shield_Foreground) {
        GetWindowThreadProcessId(GetForegroundWindow(), &targetPid);
        // Safety: Do not target self or system idle
        if (targetPid <= 4 || targetPid == GetCurrentProcessId()) {
             result.executed = false; result.reversible = true; result.committed = false;
             result.reason = "InvalidTarget"; decision.isReversible = false; return result;
        }
    }

    // [SECURITY FIX] TOCTOU Mitigation: Open Handle FIRST
    DWORD accessMask = PROCESS_QUERY_LIMITED_INFORMATION;
    switch (decision.selectedAction) {
        case BrainAction::Action_MemoryTrim:
        case BrainAction::Action_MemoryHarden:
            accessMask |= PROCESS_SET_QUOTA;
            break;
        default:
            // All other actions require SET_INFORMATION because Rollback() 
            // unconditionally calls SetPriorityClass when m_wsModified is false.
            accessMask |= PROCESS_SET_INFORMATION;
            break;
    }
    m_hTarget.reset(OpenProcess(accessMask, FALSE, targetPid));
    if (!m_hTarget) {
        // Provenance: API failure must not be silent — push counterfactual for audit
        decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::TargetAccessDenied});
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "TargetAccessDenied";
        decision.isReversible = false;
        return result;
    }

    // [SECURITY PATCH] Immutable Core Check (Handle-Based)
    // Prevent "Trusted Assassin" attack via IPC/Policy using the LOCKED handle
    if (IsImmutableSystemProcess(m_hTarget.get())) {
        m_hTarget.reset();
        
        result.executed = false;
        result.reversible = false;
        result.committed = false;
        result.reason = "SecurityInterlock";
        decision.isReversible = false;
        
        static std::unordered_map<DWORD, uint64_t> s_lastImmutableLog;
        uint64_t nowLog = GetTickCount64();
        if (nowLog - s_lastImmutableLog[targetPid] > 60000) {
            Log("[SECURITY] Denied action on Immutable Core Process: " + std::to_string(targetPid));
            s_lastImmutableLog[targetPid] = nowLog;
        }
        return result;
    }

    // Handle is valid and safe; proceed.

    // 3. Capture State (For potential manual rollback, though we intend to commit)
    m_originalPriorityClass = GetPriorityClass(m_hTarget.get());
    GetProcessWorkingSetSizeEx(m_hTarget.get(), &m_originalMinWS, &m_originalMaxWS, &m_originalWSFlags);
    if (m_originalPriorityClass == 0 && m_originalMinWS == 0) {
        m_hTarget.reset();
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "StateCaptureFailed";
        decision.isReversible = false;
        return result;
    }

    // 4. Execute Action (Step 3: One Action Type Only)
    BOOL success = FALSE;
    if (decision.selectedAction == BrainAction::Throttle_Mild) {
        success = SetPriorityClass(m_hTarget.get(), BELOW_NORMAL_PRIORITY_CLASS);
    } 
    else if (decision.selectedAction == BrainAction::Shield_Foreground) {
        success = SetPriorityClass(m_hTarget.get(), ABOVE_NORMAL_PRIORITY_CLASS);
    }
    else if (decision.selectedAction == BrainAction::Suspend_Services) {
        // [PATCH] Trigger Service Suspension
        SuspendBackgroundServices();
        success = TRUE;
    }
    else if (decision.selectedAction == BrainAction::Release_Pressure) {
        // [PATCH] Apply I/O Boost (Pressure Relief)
        if (m_hTarget) {
            // Use our updated BOOL helper from tweaks.h
            success = SetProcessIoPriority(GetProcessId(m_hTarget.get()), 3); // 3 = High
        } else {
             // Fallback: Target foreground
             DWORD fgPid = 0;
             GetWindowThreadProcessId(GetForegroundWindow(), &fgPid);
             if (fgPid > 4) {
                 success = SetProcessIoPriority(fgPid, 3);
             }
        }
    }
    // Deprecated backward calls to Ring 2 (MemoryOptimizer) have been removed to strictly 
    // enforce the Sandbox Barrier. Duplicate Suspend_Services block has also been removed.
    else if (decision.selectedAction == BrainAction::Boost_Process) {
        // [FIX] Active Enforcer: High Priority for Games/Browsers
        // If target is self (default), switch to foreground window
        if (targetPid == GetCurrentProcessId()) {
             m_hTarget.reset(); // Auto-closes current
             GetWindowThreadProcessId(GetForegroundWindow(), &targetPid);
             m_hTarget.reset(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid));
        }

        if (m_hTarget) {
            success = SetPriorityClass(m_hTarget.get(), HIGH_PRIORITY_CLASS);
        }
    }
    else if (decision.selectedAction == BrainAction::Action_MemoryHarden) {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(m_hTarget.get(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            SIZE_T current = pmc.WorkingSetSize;
            if (current > 200 * 1024 * 1024) {
                success = SetProcessWorkingSetSizeEx(m_hTarget.get(), current, (SIZE_T)-1, QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE);
                if (success) m_wsModified = true;
            }
        }
    }
    else if (decision.selectedAction == BrainAction::Action_MemoryTrim) {
        success = SetProcessWorkingSetSizeEx(m_hTarget.get(), 4096, 256 * 1024 * 1024, 0);
        if (success) m_wsModified = true;
    }
    
    if (success) {
        m_actionApplied = true;
        m_leaseStart = GetTickCount64(); // Start the Lease Clock
        
        // [SECURITY PATCH] Update Shared Ledger for Crash Recovery
        if (m_originalPriorityClass != 0) {
            UpdateSessionLedger(targetPid, m_originalPriorityClass, 0, true);
        }

        // COMMIT: We do NOT rollback automatically.
        result.executed = true;
        result.reversible = true;
        result.committed = true;
        result.reason = "LeaseStarted";
        
        // Grant Authority
        decision.isReversible = true; 
    } else {
        // Provenance: Win32 API failure must not be silent — push counterfactual for audit
        decision.rejectedAlternatives.push_back({decision.selectedAction, RejectionReason::ApiFailure});
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "SysCallFailed";
        
        // [FIX] Prevent C6387: Check handle validity before closing
        m_hTarget.reset();
        decision.isReversible = false;
    }

    return result;
}

void SandboxExecutor::Rollback() {
    // [PATCH] Global Service Restoration
    // If the applied action was Suspend_Services, we must resume them.
    // (Note: We detect this by checking if m_hTarget is null, as Suspend_Services doesn't use a target handle,
    //  OR we could track the action type explicitly. For now, calling Resume is safe even if not suspended.)
    ResumeBackgroundServices();

    if (m_actionApplied && m_hTarget) {
        if (m_wsModified) {
            SetProcessWorkingSetSizeEx(m_hTarget.get(), m_originalMinWS, m_originalMaxWS, 0);
            m_wsModified = false;
        } else {
            SetPriorityClass(m_hTarget.get(), m_originalPriorityClass);
        }
        
        // [SECURITY PATCH] Clear from Ledger
        UpdateSessionLedger(GetProcessId(m_hTarget.get()), 0, 0, false);

        m_actionApplied = false;
        
        // Cooldown Start: Mark the exact moment authority was revoked.
        m_lastReleaseTime = GetTickCount64();
    }
}

bool SandboxExecutor::IsLeaseActive() const {
    return m_actionApplied;
}

SandboxExecutor::~SandboxExecutor() {
    // [SECURITY PATCH] Emergency Rollback on Destruction
    // If the object is dying, we must release the lease.
    // (This covers standard shutdowns, but not hard crashes - handled by Watchdog/Ledger)
    if (m_actionApplied && m_hTarget) {
        Rollback(); 
    }

    // m_hTarget auto-closes via UniqueHandle
}

bool SandboxExecutor::IsReversible(BrainAction action) const {
    // Helper used for pre-checks, though logic is now embedded in TryExecute
    return (action == BrainAction::Throttle_Mild || action == BrainAction::Maintain);
}

// ----------------------------------------------------------------------
// [ACTUATION] Centralized Safety Primitives Implementation
// ----------------------------------------------------------------------

bool SandboxExecutor::EnforceEcoQoS(DWORD pid, bool enable) {
    if (pid <= 4) return false;
    
    // 1. Open Handle
    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return false;

    // 2. Security Check (The Gatekeeper)
    if (IsImmutableSystemProcess(hProc.get())) {
        Log("[SANDBOX] Blocked EcoQoS on Immutable Process: " + std::to_string(pid));
        return false;
    }

    // 3. Actuate
    PROCESS_POWER_THROTTLING_STATE PowerThrottling = {};
    PowerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    PowerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    PowerThrottling.StateMask = enable ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0;

    if (SetProcessInformation(hProc.get(), ProcessPowerThrottling, &PowerThrottling, sizeof(PowerThrottling))) {
        return true;
    }
    return false;
}

bool SandboxExecutor::EnforceAffinity(DWORD pid, DWORD_PTR mask) {
    if (pid <= 4 || mask == 0) return false;

    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return false;

    if (IsImmutableSystemProcess(hProc.get())) {
        Log("[SANDBOX] Blocked Affinity Change on Immutable Process: " + std::to_string(pid));
        return false;
    }

    if (SetProcessAffinityMask(hProc.get(), mask)) {
        return true;
    }
    return false;
}

bool SandboxExecutor::EnforceTrim(DWORD pid) {
    if (pid <= 4) return false;

    // QUOTA rights required for Working Set
    UniqueHandle hProc(OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return false;

    if (IsImmutableSystemProcess(hProc.get())) {
        return false;
    }

    if (EmptyWorkingSet(hProc.get())) {
        return true;
    }
    return false;
}

bool SandboxExecutor::EnforcePriority(DWORD pid, DWORD priorityClass) {
    if (pid <= 4) return false;

    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return false;

    if (IsImmutableSystemProcess(hProc.get())) {
        Log("[SANDBOX] Blocked Priority change on Immutable Process: " + std::to_string(pid));
        return false;
    }

    if (SetPriorityClass(hProc.get(), priorityClass)) {
        return true;
    }
    return false;
}
