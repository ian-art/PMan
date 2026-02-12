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

// [SECURITY PATCH] Helper to maintain the Shared Ledger
static void UpdateLeaseLedger(DWORD pid, DWORD prio, DWORD_PTR affinity, bool active) {
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(LeaseLedger), L"Local\\PManSessionLedger");
    if (!hMap) return;
    
    // We map only briefly to update state
    LeaseLedger* ledger = (LeaseLedger*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LeaseLedger));
    if (ledger) {
        if (active) {
            // FIND FREE SLOT
            for (int i = 0; i < LeaseLedger::MAX_LEASES; i++) {
                if (!ledger->entries[i].isActive) {
                    ledger->entries[i].pid = pid;
                    ledger->entries[i].originalPriority = prio;
                    ledger->entries[i].originalAffinity = affinity;
                    ledger->entries[i].leaseStartTime = GetTickCount64();
                    ledger->entries[i].isActive = true;
                    break;
                }
            }
        } else {
            // REMOVE ENTRY
            for (int i = 0; i < LeaseLedger::MAX_LEASES; i++) {
                if (ledger->entries[i].isActive && ledger->entries[i].pid == pid) {
                    ledger->entries[i].isActive = false;
                    break;
                }
            }
        }
        UnmapViewOfFile(ledger);
    }
    // Handle is closed immediately; the Mapping object persists if other handles (Watchdog) are open,
    // or destroys if count=0. We rely on Watchdog opening it when needed or keeping it open.
    // Ideally, PManContext should hold the handle, but this stateless approach suffices for crash recovery.
    CloseHandle(hMap); 
}

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
        decision.selectedAction != BrainAction::Optimize_Memory && // [PATCH] Allow Memory
        decision.selectedAction != BrainAction::Optimize_Memory_Gentle &&
        decision.selectedAction != BrainAction::Suspend_Services) { // [PATCH] Allow Service Suspension
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
    DWORD targetPid = GetCurrentProcessId();
    if (decision.selectedAction == BrainAction::Shield_Foreground) {
        GetWindowThreadProcessId(GetForegroundWindow(), &targetPid);
        // Safety: Do not target self or system idle
        if (targetPid <= 4 || targetPid == GetCurrentProcessId()) {
             result.executed = false; result.reversible = true; result.committed = false;
             result.reason = "InvalidTarget"; decision.isReversible = false; return result;
        }
    }

    // [SECURITY FIX] TOCTOU Mitigation: Open Handle FIRST
    m_hTarget = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!m_hTarget) {
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "AccessDenied";
        decision.isReversible = false;
        return result;
    }

    // [SECURITY PATCH] Immutable Core Check (Handle-Based)
    // Prevent "Trusted Assassin" attack via IPC/Policy using the LOCKED handle
    if (IsImmutableSystemProcess(m_hTarget)) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
        
        result.executed = false;
        result.reversible = false;
        result.committed = false;
        result.reason = "SecurityInterlock";
        decision.isReversible = false;
        Log("[SECURITY] Denied action on Immutable Core Process: " + std::to_string(targetPid));
        return result;
    }

    // Handle is valid and safe; proceed.

    // 3. Capture State (For potential manual rollback, though we intend to commit)
    m_originalPriorityClass = GetPriorityClass(m_hTarget);
    if (m_originalPriorityClass == 0) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
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
        success = SetPriorityClass(m_hTarget, BELOW_NORMAL_PRIORITY_CLASS);
    } 
    else if (decision.selectedAction == BrainAction::Shield_Foreground) {
        success = SetPriorityClass(m_hTarget, ABOVE_NORMAL_PRIORITY_CLASS);
    }
    else if (decision.selectedAction == BrainAction::Optimize_Memory || 
             decision.selectedAction == BrainAction::Optimize_Memory_Gentle) {
        // [PATCH] Trigger Memory Optimizer
        // We use the global instance to perform the smart trim
        DWORD fgPid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fgPid);
        g_memoryOptimizer.SmartMitigate(fgPid);
        success = TRUE; // Dispatched to background thread
    }
    else if (decision.selectedAction == BrainAction::Suspend_Services) {
        // [PATCH] Trigger Service Suspension
        SuspendBackgroundServices();
        success = TRUE;
    }
    else if (decision.selectedAction == BrainAction::Boost_Process) {
        // [FIX] Active Enforcer: High Priority for Games/Browsers
        // If target is self (default), switch to foreground window
        if (targetPid == GetCurrentProcessId()) {
             CloseHandle(m_hTarget);
             GetWindowThreadProcessId(GetForegroundWindow(), &targetPid);
             m_hTarget = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
        }

        if (m_hTarget) {
            success = SetPriorityClass(m_hTarget, HIGH_PRIORITY_CLASS);
        }
    }
    
    if (success) {
        m_actionApplied = true;
        m_leaseStart = GetTickCount64(); // Start the Lease Clock
        
        // [SECURITY PATCH] Update Shared Ledger for Crash Recovery
        if (m_originalPriorityClass != 0) {
            UpdateLeaseLedger(targetPid, m_originalPriorityClass, 0, true);
        }

        // COMMIT: We do NOT rollback automatically.
        result.executed = true;
        result.reversible = true;
        result.committed = true;
        result.reason = "LeaseStarted";
        
        // Grant Authority
        decision.isReversible = true; 
    } else {
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "SysCallFailed";
        
        // [FIX] Prevent C6387: Check handle validity before closing
        if (m_hTarget) CloseHandle(m_hTarget);
        m_hTarget = nullptr;
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
        SetPriorityClass(m_hTarget, m_originalPriorityClass);
        
        // [SECURITY PATCH] Clear from Ledger
        UpdateLeaseLedger(GetProcessId(m_hTarget), 0, 0, false);

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

    if (m_hTarget) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
    }
}

bool SandboxExecutor::IsReversible(BrainAction action) const {
    // Helper used for pre-checks, though logic is now embedded in TryExecute
    return (action == BrainAction::Throttle_Mild || action == BrainAction::Maintain);
}
