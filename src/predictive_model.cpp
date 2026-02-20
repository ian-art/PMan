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

#include "predictive_model.h"
#include "logger.h"
#include "utils.h"
#include <cmath>
#include <algorithm>
#include <fstream>
#include <filesystem>

void PredictiveModel::Initialize() {
    Log("[INIT] Predictive Model Initialized.");

    std::lock_guard<std::mutex> lock(m_mtx);
    std::filesystem::path path = GetLogPath() / L"brain.bin";
    std::filesystem::path backupPath = GetLogPath() / L"brain.bin.bak";

    auto tryLoad = [&](const std::filesystem::path& p) -> bool {
        if (!std::filesystem::exists(p)) return false;
        
        // Scope the file stream to ensure the handle is released before potential deletion
        {
            std::ifstream f(p, std::ios::binary);
            if (!f.is_open()) return false;
            
            uint32_t magic = 0;
            // Verify Magic Signature and Bounds
            if (f.read(reinterpret_cast<char*>(&magic), sizeof(magic)) && magic == 0x4E415242) {
                size_t size = 0;
                if (f.read(reinterpret_cast<char*>(&size), sizeof(size)) && size < 100000) {
                    m_stats.clear(); // Ensure clean slate before loading
                    for (size_t i = 0; i < size; ++i) {
                        ModelKey key = {};
                        PredictionStats stats = {};
                        f.read(reinterpret_cast<char*>(&key), sizeof(ModelKey));
                        f.read(reinterpret_cast<char*>(&stats), sizeof(PredictionStats));
                        if (!f.good()) break;
                        m_stats[key] = stats;
                    }
                    return true;
                }
            }
        } // std::ifstream goes out of scope and closes the file handle here
        
        // If execution reaches here, the file exists but failed validation.
        // It is corrupted. Delete it immediately to maintain system hygiene.
        std::error_code ec;
        std::filesystem::remove(p, ec);
        return false;
    };

    if (tryLoad(path)) {
        Log("[BRAIN] Loaded " + std::to_string(m_stats.size()) + " learned patterns.");
    } else if (tryLoad(backupPath)) {
        Log("[BRAIN] Main file corrupted/missing. Recovered " + std::to_string(m_stats.size()) + " patterns from backup.");
    } else {
        Log("[BRAIN] No valid brain data found. Starting fresh.");
    }
}

void PredictiveModel::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mtx);
    std::filesystem::path path = GetLogPath() / L"brain.bin";
    std::filesystem::path backupPath = GetLogPath() / L"brain.bin.bak";

    // Backup existing known-good brain before writing a new one
    if (std::filesystem::exists(path)) {
        std::error_code ec;
        std::filesystem::copy_file(path, backupPath, std::filesystem::copy_options::overwrite_existing, ec);
    }

    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) {
        const uint32_t MAGIC_SIG = 0x4E415242; // "BRAN"
        f.write(reinterpret_cast<const char*>(&MAGIC_SIG), sizeof(MAGIC_SIG));

        size_t size = m_stats.size();
        f.write(reinterpret_cast<const char*>(&size), sizeof(size));

        for (const auto& [key, stats] : m_stats) {
            f.write(reinterpret_cast<const char*>(&key), sizeof(ModelKey));
            f.write(reinterpret_cast<const char*>(&stats), sizeof(PredictionStats));
        }
        Log("[BRAIN] Saved " + std::to_string(size) + " patterns to brain.bin");
    }
}

CostVector PredictiveModel::QuantizeRealOutcome(const OptimizationFeedback& fb) {
    CostVector cv = {0, 0, 0, 0};
    
    // Map Real Deltas to Cost Scale (-5 to +5)
    // CPU: 1 pt ~= 5% load change
    cv.cpuDelta = static_cast<int>(fb.cpuDelta / 5.0);
    
    // Disk: 1 pt ~= 0.5 queue depth change
    cv.diskDelta = static_cast<int>(fb.diskDelta * 2.0);
    
    // Latency: 1 pt ~= 1ms change (aggressive for interactivity)
    cv.latencyRisk = static_cast<int>(fb.latencyDelta); 
    
    // Clamp to valid range
    auto clamp = [](int v) { return (std::max)(-5, (std::min)(5, v)); };
    cv.cpuDelta = clamp(cv.cpuDelta);
    cv.diskDelta = clamp(cv.diskDelta);
    cv.latencyRisk = clamp(cv.latencyRisk);
    
    return cv;
}

ConsequenceResult PredictiveModel::Correct(const ConsequenceResult& raw, SystemMode mode, DominantPressure pressure, AllowedActionClass action) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    ModelKey key = { mode, pressure, action };
    auto it = m_stats.find(key);
    
    // If no history, trust the static model 100%
    if (it == m_stats.end()) {
        ConsequenceResult safeRaw = raw;
        safeRaw.confidence = 1.0; // Static model is baseline truth
        return safeRaw;
    }
    
    const PredictionStats& stats = it->second;
    ConsequenceResult corrected = raw;
    corrected.confidence = stats.confidence;
    
    // 1. Apply Mean Error Correction
    // If we consistently underestimate cost (positive error), add it to future predictions.
    corrected.cost.cpuDelta += static_cast<int>(stats.meanErrorCpu);
    corrected.cost.diskDelta += static_cast<int>(stats.meanErrorDisk);
    corrected.cost.latencyRisk += static_cast<int>(stats.meanErrorLatency);
    
    // 2. Apply Confidence Penalty (Section 8)
    // "Prediction error may only reduce confidence, never increase authority."
    if (stats.confidence < 0.6) {
        // Low confidence: Dampen benefits, Amplify risks
        auto penalize = [](int& val) {
            if (val < 0) val /= 2; // Reduce predicted benefit
            else val += 1;         // Increase predicted cost
        };
        penalize(corrected.cost.cpuDelta);
        penalize(corrected.cost.diskDelta);
        penalize(corrected.cost.latencyRisk);
        
        // Critical Safety: If confidence is very low, force Unsafe to prefer Inaction
        if (stats.confidence < 0.3) {
            corrected.isSafe = false;
        }
    }
    
    return corrected;
}

void PredictiveModel::Feedback(SystemMode mode, DominantPressure pressure, AllowedActionClass action, 
              const CostVector& predicted, const OptimizationFeedback& realOutcome) {
    
    std::lock_guard<std::mutex> lock(m_mtx);
    
    CostVector actual = QuantizeRealOutcome(realOutcome);
    
    ModelKey key = { mode, pressure, action };
    PredictionStats& stats = m_stats[key];
    
    // Calculate Error (Actual - Predicted)
    // Positive Error = Real outcome was worse (higher cost) than predicted
    double errCpu = actual.cpuDelta - predicted.cpuDelta;
    double errDisk = actual.diskDelta - predicted.diskDelta;
    double errLat = actual.latencyRisk - predicted.latencyRisk;
    
    // [PATCH] Fast-Start: Learn fast (0.35) for first 15 samples, then stabilize
    double alpha = (stats.sampleCount < 15) ? 0.35 : LEARNING_RATE;

    // Update Mean Error (Exponential Moving Average)
    stats.meanErrorCpu = (stats.meanErrorCpu * (1.0 - alpha)) + (errCpu * alpha);
    stats.meanErrorDisk = (stats.meanErrorDisk * (1.0 - alpha)) + (errDisk * alpha);
    stats.meanErrorLatency = (stats.meanErrorLatency * (1.0 - alpha)) + (errLat * alpha);
    
    stats.sampleCount++;
    
    // Update Variance (Simplified L1 Norm)
    double totalError = std::abs(errCpu) + std::abs(errDisk) + std::abs(errLat);
    stats.variance = (stats.variance * (1.0 - alpha)) + (totalError * alpha);
    
    // Update Confidence (Inverse of Variance)
    // Base confidence 1.0, reduces as variance increases
    stats.confidence = 1.0 / (1.0 + (stats.variance * 0.5));
    
    // Audit Logging
    if (m_logs.size() >= MAX_LOG_HISTORY) m_logs.pop_front();
    m_logs.push_back({mode, pressure, action, predicted, actual, GetTickCount64()});
}
