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

#ifndef PMAN_PREDICTION_LEDGER_H
#define PMAN_PREDICTION_LEDGER_H

#include "shadow_executor.h" // For PredictedStateDelta
#include "reality_sampler.h" // For ObservedStateDelta

struct PredictionError {
    double cpuError;
    double thermalError;
    double latencyError;
};

class PredictionLedger {
public:
    // Pure statistical observer.
    // Error = Observed - Predicted.
    // No normalization, no scaling, no thresholds.
    PredictionError Compute(const PredictedStateDelta& predicted, const ObservedStateDelta& observed);
};

#endif // PMAN_PREDICTION_LEDGER_H
