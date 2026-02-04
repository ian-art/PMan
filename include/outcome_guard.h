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

#ifndef PMAN_OUTCOME_GUARD_H
#define PMAN_OUTCOME_GUARD_H

#include "types.h"

struct OutcomeGuardConfig {
    int maxCpuWorsening;     // e.g. +5%
    int maxLatencyWorsening; // e.g. +20 ms
};

class OutcomeGuard {
public:
    OutcomeGuard();

    // Reactive Rollback Guard
    // Returns TRUE if reality is significantly worse than prediction.
    // Hard Rule: No statistics, no history, just immediate threshold check.
    bool ShouldAbort(const PredictedStateDelta& predicted, const ObservedStateDelta& observed);

private:
    OutcomeGuardConfig m_config;
};

#endif // PMAN_OUTCOME_GUARD_H
