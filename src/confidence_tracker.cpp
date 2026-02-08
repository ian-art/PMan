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

#include "confidence_tracker.h"
#include "context.h"
#include <limits> // For quiet_NaN

void ConfidenceTracker::RunningStat::Push(double x) {
    m_n++;
    // [PATCH] Adaptive EMA: Reduced to 0.05 for stability (approx 40 samples history)
    // This prevents confidence from fluctuating too wildly, making Policy tuning easier.
    constexpr double alpha = 0.05; 

    if (m_n == 1.0) {
        m_newM = x;
        m_newS = 0.0;
    } else {
        double diff = x - m_newM;
        double inc = alpha * diff;
        m_newM += inc;
        
        // EMA Variance: (1-a)*Var + a*diff^2
        // We reuse m_newS to store Variance directly instead of SumSq
        m_newS = (1.0 - alpha) * m_newS + alpha * (diff * diff);
    }
}

double ConfidenceTracker::RunningStat::Variance() const {
    // [PATCH] m_newS now holds the EMA Variance directly
    return m_newS;
}

void ConfidenceTracker::Observe(const PredictionError& error) {
    m_cpuStat.Push(static_cast<double>(error.cpuError));
    m_thermalStat.Push(static_cast<double>(error.thermalError));
    m_latencyStat.Push(static_cast<double>(error.latencyError));
}

ConfidenceMetrics ConfidenceTracker::GetMetrics() const {
    // [FAULT INJECTION]
    if (PManContext::Get().fault.confidenceInvalid) {
        return {
            std::numeric_limits<double>::quiet_NaN(),
            std::numeric_limits<double>::quiet_NaN(),
            std::numeric_limits<double>::quiet_NaN()
        };
    }

    return {
        m_cpuStat.Variance(),
        m_thermalStat.Variance(),
        m_latencyStat.Variance()
    };
}

// [INVESTIGATOR] Forcefully restore confidence after a False Alarm
void ConfidenceTracker::ForceConfidence(double amount) {
    // Reset variances to 0 (or reduce them significantly) to represent "Clear Skies"
    // Since we use Welford's algorithm, we can't easily "subtract" variance.
    // Instead, we re-initialize the stats if the boost is absolute (1.0).
    
    if (amount >= 1.0) {
        m_cpuStat = RunningStat();
        m_thermalStat = RunningStat();
        m_latencyStat = RunningStat();
    }
}
