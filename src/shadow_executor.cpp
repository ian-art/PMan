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

PredictedStateDelta ShadowExecutor::Simulate(const ArbiterDecision& decision, const SystemSignalSnapshot& telemetry) {
    PredictedStateDelta delta = { 0, 0, 0 };

    switch (decision.selectedAction) {
        case BrainAction::Maintain:
            delta = {0, 0, 0};
            break;

        case BrainAction::Throttle_Mild:
            // Simulation: Mild throttling reduces CPU load by ~10% of current usage
            // It rarely adds latency unless load is already critically low (starvation)
            delta.cpuLoadDelta = -(telemetry.cpuLoad * 0.10);
            delta.latencyDelta = (telemetry.cpuLoad > 90.0) ? 2.0 : 0.0;
            break;

        case BrainAction::Throttle_Aggressive:
            // Simulation: Aggressive throttling reduces CPU load by ~25%
            // But significantly risks latency if user is active or load is high
            delta.cpuLoadDelta = -(telemetry.cpuLoad * 0.25);
            delta.latencyDelta = (telemetry.cpuLoad * 0.20); // 20% latency penalty risk
            delta.thermalDelta = -2.0; // Good for cooling
            break;

        case BrainAction::Optimize_Memory:
            // Simulation: Trimming spikes CPU and Latency momentarily
            delta.cpuLoadDelta = 5.0; 
            delta.latencyDelta = 15.0; // Hard faults cause stutter
            break;

        case BrainAction::Suspend_Services:
            // Simulation: Stopping services frees minimal CPU, mostly RAM
            delta.cpuLoadDelta = -1.0;
            break;

        case BrainAction::Release_Pressure:
            // Simulation: Removing clamps restores natural CPU demand (load goes UP)
            // But latency (responsiveness) improves drastically
            delta.cpuLoadDelta = 5.0; 
            delta.latencyDelta = -10.0;
            break;

        case BrainAction::Probation:
            // [PHASE 3] Simulation: Probation clamps a suspicious process hard.
            // CPU load drops significantly (due to Low Priority).
            // Latency increases for the target, but system responsiveness improves.
            delta.cpuLoadDelta = -(telemetry.cpuLoad * 0.30); // 30% reduction estimate
            delta.latencyDelta = -5.0; // System latency improves (target suffers, but we don't care)
            delta.thermalDelta = -1.0;
            break;

        default:
            delta = {0, 0, 0};
            break;
    }

    return delta;
}
