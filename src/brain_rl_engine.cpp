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

#include "brain_rl_engine.h"
#include "logger.h"
#include "utils.h"
#include <numeric>
#include <fstream>
#include <algorithm>

PolicyOptimizer::PolicyOptimizer() {
    m_policyPath = GetLogPath() / L"policy_v1.bin";
}

PolicyOptimizer::~PolicyOptimizer() {
    Shutdown();
}

void PolicyOptimizer::Initialize() {
    LoadPolicy();
    Log("[OPTIMIZER] Phase 6 Engine Initialized. Policy loaded.");
}

void PolicyOptimizer::Shutdown() {
    SavePolicy();
}

void PolicyOptimizer::OnFeedback(const OptimizationFeedback& feedback) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_history.push_back(feedback);

    // Bounded history (Rolling window)
    if (m_history.size() > 1000) {
        m_history.erase(m_history.begin(), m_history.begin() + 100);
    }
}

double PolicyOptimizer::CalculateRegret(const OptimizationFeedback& fb) {
    // Section 7: Regret-Based Optimization
    // Regret = OutcomeCost(SelectedAction) - OutcomeCost(NoAction)
    
    // Cost Function: Weighted sum of deltas (Higher is worse)
    // Note: If we throttled (Action), we expect negative deltas (improvement).
    // If deltas are positive (worse), Regret is high.
    
    double cost = (fb.cpuDelta * m_currentPolicy.cpuWeight) +
                  (fb.memDelta * m_currentPolicy.memWeight) +
                  (fb.diskDelta * m_currentPolicy.diskWeight) +
                  (fb.latencyDelta * m_currentPolicy.latencyWeight);

    // If UserInterrupted, Infinite Regret (Action was annoying)
    if (fb.userInterrupted) return 1000.0;

    // Conceptual "NoAction" Baseline:
    // If we did nothing, deltas would theoretically be 0 (or strictly trend with load).
    // So Regret ~= Cost.
    // Negative Cost (Improvement) means Negative Regret (Benefit).
    return cost;
}

PolicyParameters PolicyOptimizer::Optimize() {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    if (m_history.empty()) return m_currentPolicy;

    // 1. Analyze recent history
    double totalRegret = 0;
    OptimizationFeedback avgFb = {};
    
    int samples = 0;
    for (auto it = m_history.rbegin(); it != m_history.rend() && samples < 50; ++it, ++samples) {
        totalRegret += CalculateRegret(*it);
        avgFb.cpuDelta += it->cpuDelta;
        avgFb.diskDelta += it->diskDelta;
    }
    avgFb.cpuDelta /= (samples > 0 ? samples : 1);
    avgFb.diskDelta /= (samples > 0 ? samples : 1);

    double avgRegret = totalRegret / (samples > 0 ? samples : 1);

    // 2. Tune Parameters (Simple Gradient Descent Placeholder)
    TuneParameters(avgRegret, avgFb);

    // 3. Persist occasionally
    static uint64_t lastSave = 0;
    if (GetTickCount64() - lastSave > 300000) { // 5 minutes
        SavePolicy();
        lastSave = GetTickCount64();
    }

    return m_currentPolicy;
}

void PolicyOptimizer::TuneParameters(double avgRegret, const OptimizationFeedback& recentAvg) {
    // Section 5: Allowed Changes
    // If Regret is high (System getting worse), tighten thresholds.
    
    if (avgRegret > 5.0) { // Arbitrary high regret threshold
        // System is unstable/degrading.
        // Reaction: Become more sensitive (lower thresholds) to catch pressure earlier?
        // OR: If we are acting and it's bad, maybe we are acting too much?
        
        // Simple logic: If CPU is worsening (positive delta), lower CPU threshold to catch it earlier.
        if (recentAvg.cpuDelta > 0) {
            m_currentPolicy.cpuThreshold = std::clamp(m_currentPolicy.cpuThreshold - 0.01, 0.50, 0.95);
        }
    }
    else if (avgRegret < -5.0) {
        // System is improving significantly.
        // We can afford to be looser (higher thresholds) to interfere less.
        m_currentPolicy.cpuThreshold = std::clamp(m_currentPolicy.cpuThreshold + 0.005, 0.50, 0.95);
    }
}

void PolicyOptimizer::LoadPolicy() {
    std::ifstream f(m_policyPath, std::ios::binary);
    if (f.is_open()) {
        f.read(reinterpret_cast<char*>(&m_currentPolicy), sizeof(PolicyParameters));
        f.close();
    }
}

void PolicyOptimizer::SavePolicy() {
    std::ofstream f(m_policyPath, std::ios::binary);
    if (f.is_open()) {
        f.write(reinterpret_cast<const char*>(&m_currentPolicy), sizeof(PolicyParameters));
        f.close();
    }
}
