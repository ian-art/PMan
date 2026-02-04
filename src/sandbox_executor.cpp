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

SandboxResult SandboxExecutor::TryExecute(const ArbiterDecision& decision) {
    SandboxResult result = { false, false, "None" };

    // 1. Strict Allowlist (Reversibility Check)
    if (!IsReversible(decision.selectedAction)) {
        result.executed = false;
        result.reversible = false;
        result.reason = "NonReversibleAction";
        return result;
    }

    if (decision.selectedAction == BrainAction::Maintain) {
        result.executed = false;
        result.reversible = true;
        result.reason = "NoAction";
        return result;
    }

    // 2. Target Selection (Zero-Risk Probe: Target Self)
    // We demonstrate authority by manipulating our own process priority.
    m_hTarget = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!m_hTarget) {
        result.executed = false;
        result.reversible = true;
        result.reason = "AccessDenied";
        return result;
    }

    // 3. Capture State (For Rollback)
    m_originalPriorityClass = GetPriorityClass(m_hTarget);
    if (m_originalPriorityClass == 0) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
        result.executed = false;
        result.reversible = true;
        result.reason = "StateCaptureFailed";
        return result;
    }

    // 4. Execute Action
    // Mapping: Throttle -> Below Normal
    BOOL success = FALSE;
    if (decision.selectedAction == BrainAction::Throttle_Mild || 
        decision.selectedAction == BrainAction::Throttle_Aggressive) {
        success = SetPriorityClass(m_hTarget, BELOW_NORMAL_PRIORITY_CLASS);
    } 
    // Note: Other reversible actions can be added here
    
    if (success) {
        m_actionApplied = true;
        result.executed = true;
        result.reversible = true;
        result.reason = "Executed";
    } else {
        result.executed = false;
        result.reversible = true;
        result.reason = "SysCallFailed";
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
    }

    return result;
}

void SandboxExecutor::Rollback() {
    if (m_actionApplied && m_hTarget) {
        // Guaranteed Restoration
        SetPriorityClass(m_hTarget, m_originalPriorityClass);
        m_actionApplied = false;
    }

    if (m_hTarget) {
        CloseHandle(m_hTarget);
        m_hTarget = nullptr;
    }
}

bool SandboxExecutor::IsReversible(BrainAction action) const {
    switch (action) {
        case BrainAction::Throttle_Mild:
        case BrainAction::Throttle_Aggressive:
            return true; // Priority changes are reversible
        
        case BrainAction::Maintain:
            return true; // Doing nothing is reversible

        case BrainAction::Optimize_Memory:
        case BrainAction::Suspend_Services:
        case BrainAction::Release_Pressure:
        default:
            return false; // Destructive or complex state changes
    }
}
