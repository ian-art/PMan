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

#include "outcome_guard.h"

OutcomeGuard::OutcomeGuard() {
    // Hard-coded Safety Margins
    m_config.maxCpuWorsening = 5;      // Abort if CPU load is +5% worse than predicted
    m_config.maxLatencyWorsening = 20; // Abort if Latency is +20ms worse than predicted
}

bool OutcomeGuard::ShouldAbort(const PredictedStateDelta& predicted, const ObservedStateDelta& observed) {
    // Rule: If observed is worse than predicted by more than a fixed margin -> Abort
    
    // Check CPU (Positive delta means load increased)
    // If we predicted -5% (benefit) and got +2% (worse), diff is +7%.
    double cpuDiff = observed.cpuLoadDelta - predicted.cpuLoadDelta;
    if (cpuDiff > (double)m_config.maxCpuWorsening) {
        return true;
    }

    // Check Latency
    double latDiff = observed.latencyDelta - predicted.latencyDelta;
    if (latDiff > (double)m_config.maxLatencyWorsening) {
        return true;
    }

    return false;
}
