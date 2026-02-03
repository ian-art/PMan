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

#ifndef PMAN_PREDICTIVE_MODEL_H
#define PMAN_PREDICTIVE_MODEL_H

#include "types.h"
#include <mutex>
#include <unordered_map>
#include <deque>

class PredictiveModel {
public:
    void Initialize();
    void Shutdown();

    // Section 7 Step 4: Correct the Model
    // Wraps the raw ConsequenceResult with historical error corrections
    ConsequenceResult Correct(const ConsequenceResult& raw, SystemMode mode, DominantPressure pressure, AllowedActionClass action);

    // Section 7 Step 2 & 3: Track and Aggregate
    void Feedback(SystemMode mode, DominantPressure pressure, AllowedActionClass action, 
                  const CostVector& predicted, const OptimizationFeedback& realOutcome);

private:
    struct ModelKey {
        SystemMode mode;
        DominantPressure pressure;
        AllowedActionClass action;
        
        bool operator==(const ModelKey& other) const {
            return mode == other.mode && pressure == other.pressure && action == other.action;
        }
    };

    struct KeyHash {
        std::size_t operator()(const ModelKey& k) const {
            return (std::hash<int>()((int)k.mode) ^ 
                   (std::hash<int>()((int)k.pressure) << 1)) ^ 
                   (std::hash<int>()((int)k.action) << 2);
        }
    };

    std::mutex m_mtx;
    std::unordered_map<ModelKey, PredictionStats, KeyHash> m_stats;
    std::deque<PredictionLog> m_logs; 

    // Constants
    static constexpr size_t MAX_LOG_HISTORY = 1000;
    static constexpr double LEARNING_RATE = 0.05; // Very slow adaptation (Minutes to hours)

    CostVector QuantizeRealOutcome(const OptimizationFeedback& fb);
};

#endif // PMAN_PREDICTIVE_MODEL_H
