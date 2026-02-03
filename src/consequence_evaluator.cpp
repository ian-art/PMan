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

#include "consequence_evaluator.h"
#include <algorithm>

// Section 7.1: Base Consequence Tables
// Predicts directional deltas (Section 6)
// Scale: -5 (Greatly Improves) to +5 (Severe Regression)
CostVector ConsequenceEvaluator::LookupBaseCost(AllowedActionClass action) {
    switch (action) {
        case AllowedActionClass::None:
            return {0, 0, 0, 0}; // Baseline

        case AllowedActionClass::Scheduling:
            // Threads: Minor CPU overhead, No Disk, Improves Latency, Zero Recovery
            return {0, 0, -2, 0}; 

        case AllowedActionClass::IoPrioritization:
            // IO: No CPU, Reduces Disk Queue, Neutral Latency, Low Recovery (Priority inversion risk)
            return {0, -2, 0, 1};

        case AllowedActionClass::MemoryReclaim:
            // Trim: Reduces CPU contention (Source 13), but increases Disk Pressure and Latency Risk
            return {-2, 3, 2, 3};

        case AllowedActionClass::ThermalSafety:
            // Throttle: Reduces CPU heat, Neutral Disk, Destroys Latency, Hard Recovery
            return {-3, 0, 5, 4};
            
        default:
            return {0, 0, 0, 0};
    }
}

// Section 7.2: Contextual Modifiers
CostVector ConsequenceEvaluator::ApplyContextModifiers(CostVector base, SystemMode mode, DominantPressure pressure, AllowedActionClass action) {
    CostVector final = base;

    // Modifier: Interactive Mode amplifies Latency Risk
    if (mode == SystemMode::Interactive) {
        if (final.latencyRisk > 0) {
            final.latencyRisk *= 2; // Penalty is doubled
        }
    }

    // Modifier: Thermal Recovery amplifies Recovery Cost
    if (mode == SystemMode::ThermalRecovery) {
        final.recoveryCost += 2; // Harder to step back up
    }

    // Modifier: Disk Pressure Logic
    if (pressure == DominantPressure::Disk) {
        if (action == AllowedActionClass::MemoryReclaim) {
            // "Hard Trim during Disk-Dominant mode incurs amplified Disk delta"
            final.diskDelta += 4; // Thrashing risk
            final.latencyRisk += 3; // System lockup risk
        }
        if (action == AllowedActionClass::IoPrioritization) {
            final.diskDelta -= 1; // More effective when congested
        }
    }

    // Modifier: Sustained Load Logic
    if (mode == SystemMode::SustainedLoad) {
        if (action == AllowedActionClass::Scheduling) {
            final.cpuDelta += 1; // Context switch overhead matters more here
        }
    }

    return final;
}

// Section 9: Core Decision Rule & Safety Tests
bool ConsequenceEvaluator::ValidateSafety(const CostVector& cost, SystemMode mode) {
    // 1. Latency Safety Barrier
    // In Interactive mode, we reject high latency risks regardless of other benefits
    if (mode == SystemMode::Interactive && cost.latencyRisk >= 4) {
        return false; 
    }

    // 2. Recovery Cost Barrier
    // If the cost to recover (undo action) is extreme, reject it
    if (cost.recoveryCost >= 6) {
        return false;
    }

    // 3. "Do No Harm" Principle (Section 9)
    // If the action is strictly worse than doing nothing (all positive deltas)
    if (cost.cpuDelta >= 0 && cost.diskDelta >= 0 && cost.latencyRisk >= 0 && cost.recoveryCost >= 0) {
        // Exception: If all are exactly 0 (None), it's "safe" but useless. 
        // We return true here to allow "None" to propagate if selected, 
        // though "None" usually comes from the Governor.
        // However, if we have {1, 1, 1, 1}, we must VETO.
        if (cost.cpuDelta > 0 || cost.diskDelta > 0 || cost.latencyRisk > 0 || cost.recoveryCost > 0) {
            return false;
        }
    }

    return true;
}

// Public API Implementation
ConsequenceResult ConsequenceEvaluator::Evaluate(SystemMode mode, DominantPressure pressure, AllowedActionClass action) {
    // 1. Get Base Prediction
    CostVector base = LookupBaseCost(action);

    // 2. Apply Deterministic Modifiers
    CostVector predicted = ApplyContextModifiers(base, mode, pressure, action);

    // 3. Validate against Safety Rules
    bool safe = ValidateSafety(predicted, mode);

    return { predicted, safe };
}
