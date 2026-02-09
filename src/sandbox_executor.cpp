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
        decision.selectedAction != BrainAction::Boost_Process) { // [FIX] Allow Boost
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

    m_hTarget = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!m_hTarget) {
        result.executed = false;
        result.reversible = true;
        result.committed = false;
        result.reason = "AccessDenied";
        decision.isReversible = false;
        return result;
    }

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
        
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
        decision.isReversible = false;
    }

    return result;
}

void SandboxExecutor::Rollback() {
    if (m_actionApplied && m_hTarget) {
        SetPriorityClass(m_hTarget, m_originalPriorityClass);
        m_actionApplied = false;
        
        // Cooldown Start: Mark the exact moment authority was revoked.
        m_lastReleaseTime = GetTickCount64();
    }
}

bool SandboxExecutor::IsLeaseActive() const {
    return m_actionApplied;
}

SandboxExecutor::~SandboxExecutor() {
    // Destructor ensures Handle hygiene, but DOES NOT revert priority if committed.
    if (m_hTarget) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
    }
}

bool SandboxExecutor::IsReversible(BrainAction action) const {
    // Helper used for pre-checks, though logic is now embedded in TryExecute
    return (action == BrainAction::Throttle_Mild || action == BrainAction::Maintain);
}
