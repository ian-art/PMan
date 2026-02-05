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

#ifndef PMAN_GOVERNOR_H
#define PMAN_GOVERNOR_H

#include "types.h"

class PerformanceGovernor {
public:
    // Stateless interface for determining system state and allowed actions
    // Pure function: Inputs -> Outputs. No hidden state. No side effects.
    GovernorDecision Decide(const SystemSignalSnapshot& snapshot);

    // Updates internal thresholds based on feedback from the Policy Optimizer
    void UpdatePolicy(const PolicyParameters& params);

private:
    PolicyParameters m_params; // Defaults defined in types.h constructor
    // Structure for standardized sensor data (0.0-1.0)
    struct NormalizedSignals {
        double cpu;    // 0.0 - 1.0
        double disk;   // 0.0 - 1.0
        double memory; // 0.0 - 1.0
        double latency;// 0.0 - 1.0
    };

    // Internal pipeline for processing signals and determining states
    NormalizedSignals Normalize(const SystemSignalSnapshot& raw);
    DominantPressure SelectDominant(const NormalizedSignals& signals);
    SystemMode ResolveMode(const NormalizedSignals& signals, bool userActive, bool thermal, bool security);
    AllowedActionClass DetermineActions(SystemMode mode, DominantPressure pressure);
};

#endif // PMAN_GOVERNOR_H
