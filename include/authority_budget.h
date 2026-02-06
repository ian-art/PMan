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

#ifndef PMAN_AUTHORITY_BUDGET_H
#define PMAN_AUTHORITY_BUDGET_H

#include "types.h"

class AuthorityBudget {
public:
    AuthorityBudget();

    // Check if we can afford the action cost
    bool CanSpend(int cost) const;

    // Deduct cost from the budget (Cumulative, no decay)
    void Spend(int cost);

    // Get the fixed cost for a specific action
    int GetCost(BrainAction action) const;

    // Getters for logging
    int GetUsed() const;
    int GetMax() const;
    bool IsExhausted() const;

    // Manual Recovery (Auditable)
    void ResetByExternalSignal();

    // Dynamic Policy Update
    void SetMax(int newMax);

private:
    int m_maxBudget;
    int m_usedBudget;
    bool m_exhausted;
};

#endif // PMAN_AUTHORITY_BUDGET_H
