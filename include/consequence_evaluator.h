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

#ifndef PMAN_CONSEQUENCE_EVALUATOR_H
#define PMAN_CONSEQUENCE_EVALUATOR_H

#include "types.h"

class ConsequenceEvaluator {
public:
    // Section 4 & 8: Public API
    // Answers: "If I apply this action now, what happens shortly after?"
    // Pure function: Inputs -> Futures.
    ConsequenceResult Evaluate(SystemMode mode, DominantPressure pressure, AllowedActionClass action);

private:
    // Section 7.1: Rule-Based Consequence Tables
    CostVector LookupBaseCost(AllowedActionClass action);

    // Section 7.2: Contextual Modifiers
    CostVector ApplyContextModifiers(CostVector base, SystemMode mode, DominantPressure pressure, AllowedActionClass action);

    // Section 9: Core Decision Rule
    // "If all predicted futures are worse than doing nothing -> do nothing"
    bool ValidateSafety(const CostVector& cost, SystemMode mode);
};

#endif // PMAN_CONSEQUENCE_EVALUATOR_H
