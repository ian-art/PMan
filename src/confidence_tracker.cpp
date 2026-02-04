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

void ConfidenceTracker::RunningStat::Push(double x) {
    m_n++;
    // Welford's Algorithm for streaming variance
    if (m_n == 1.0) {
        m_oldM = m_newM = x;
        m_oldS = 0.0;
    } else {
        m_newM = m_oldM + (x - m_oldM) / m_n;
        m_newS = m_oldS + (x - m_oldM) * (x - m_newM);

        // Prepare for next iteration
        m_oldM = m_newM;
        m_oldS = m_newS;
    }
}

double ConfidenceTracker::RunningStat::Variance() const {
    return (m_n > 1.0) ? m_newS / (m_n - 1.0) : 0.0;
}

void ConfidenceTracker::Observe(const PredictionError& error) {
    m_cpuStat.Push(static_cast<double>(error.cpuError));
    m_thermalStat.Push(static_cast<double>(error.thermalError));
    m_latencyStat.Push(static_cast<double>(error.latencyError));
}

ConfidenceMetrics ConfidenceTracker::GetMetrics() const {
    return {
        m_cpuStat.Variance(),
        m_thermalStat.Variance(),
        m_latencyStat.Variance()
    };
}
