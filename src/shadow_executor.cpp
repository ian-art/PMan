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

#include "shadow_executor.h"

PredictedStateDelta ShadowExecutor::Simulate(const ArbiterDecision& decision, const SystemSignalSnapshot& /*telemetry*/) {
    PredictedStateDelta delta = { 0, 0, 0 };

    switch (decision.selectedAction) {
        case BrainAction::Maintain:
            delta = {0, 0, 0};
            break;

        case BrainAction::Throttle_Mild:
            // Simulation: Mild throttling reduces CPU load slightly (-5%)
            delta = {-5, 0, 0};
            break;

        case BrainAction::Throttle_Aggressive:
            // Simulation: Aggressive throttling reduces CPU load significantly (-15%) 
            // but may increase latency (+10ms)
            delta = {-15, -1, 10};
            break;

        case BrainAction::Optimize_Memory:
            // Simulation: Memory optimization might spike CPU momentarily (+2%)
            // but reduces memory pressure (not tracked in this specific struct, so 0)
            delta = {2, 0, 5}; 
            break;

        case BrainAction::Suspend_Services:
            // Simulation: Stopping services frees resources
            delta = {-2, 0, 0};
            break;

        case BrainAction::Release_Pressure:
            // Simulation: Releasing clamps increases CPU load (+5%) and reduces latency (-5ms)
            delta = {5, 0, -5};
            break;

        default:
            delta = {0, 0, 0};
            break;
    }

    return delta;
}
