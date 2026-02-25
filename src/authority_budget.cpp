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

#include "authority_budget.h"
#include "logger.h"
#include "context.h"

AuthorityBudget::AuthorityBudget() : m_maxBudget(100), m_usedBudget(0), m_exhausted(false) {}

bool AuthorityBudget::CanSpend(int cost) const {
    // [FAULT INJECTION]
    if (PManContext::Get().fault.budgetCorruption) {
        Log("[FAULT] AuthorityBudget: Budget Corruption Simulated.");
        return false;
    }

    // Hard Lock: No spending allowed if exhausted
    if (m_exhausted) return false;
    return (m_usedBudget + cost) <= m_maxBudget;
}

void AuthorityBudget::Spend(int cost) {
    if (CanSpend(cost)) {
        m_usedBudget += cost;
        // Hard Exhaustion: Lock the budget if limit is reached
        if (m_usedBudget >= m_maxBudget) {
            m_exhausted = true;
        }
    }
}

int AuthorityBudget::GetCost(BrainAction action) const {
    // Costs reflect the risk/impact of the action
    switch (action) {
        case BrainAction::Maintain:
            return 0;

        case BrainAction::Throttle_Mild: 
            return 5;

        case BrainAction::Throttle_Aggressive: 
            return 15; // Higher cost for aggressive intervention

        case BrainAction::Optimize_Memory:
        case BrainAction::Optimize_Memory_Gentle:
            return 10; // Memory operations are expensive

        case BrainAction::Release_Pressure:
        case BrainAction::Shield_Foreground:
            return 20; // Boosting is a high-privilege action

        case BrainAction::Boost_Process:
            return 1; // [FIX] Nominal cost for "Traffic Enforcer" maintenance to prevent budget exhaustion

        case BrainAction::Suspend_Services:
            return 30; // Very high impact, drains budget quickly

        default: 
            return 5; // Default safe cost
    }
}

int AuthorityBudget::GetUsed() const { return m_usedBudget; }
int AuthorityBudget::GetMax() const { return m_maxBudget; }
bool AuthorityBudget::IsExhausted() const { return m_exhausted; }

void AuthorityBudget::ResetByExternalSignal() {
    m_usedBudget = 0;
    m_exhausted = false;
    Log("Budget: Reset (ExternalSignal)");
}

void AuthorityBudget::SetMax(int newMax) {
    m_maxBudget = newMax;
}
