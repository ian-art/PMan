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

#ifndef PMAN_POLICY_OPTIMIZER_H
#define PMAN_POLICY_OPTIMIZER_H

#include "types.h"
#include <vector>
#include <mutex>
#include <filesystem>

// The PolicyOptimizer
// "Names enforce behavior."
class PolicyOptimizer {
public:
    PolicyOptimizer();
    ~PolicyOptimizer();

    void Initialize();
    void Shutdown();

    // Core Input: Learning from Decisions and Outcomes (Section 6 & 9)
    void OnFeedback(const OptimizationFeedback& feedback);

    // Core Output: Bounded Parameter Updates (Section 5)
    // Called periodically by the main loop to tune the Governor.
    PolicyParameters Optimize();

private:
    // State
    std::mutex m_mtx;
    std::vector<OptimizationFeedback> m_history;
    PolicyParameters m_currentPolicy;
    
    // Persistence
    std::filesystem::path m_policyPath;
    void LoadPolicy();
    void SavePolicy();

    // Logic
    double CalculateRegret(const OptimizationFeedback& fb);
    void TuneParameters(double avgRegret, const OptimizationFeedback& recentAvg);
};

#endif // PMAN_POLICY_OPTIMIZER_H
