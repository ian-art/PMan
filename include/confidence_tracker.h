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

#ifndef PMAN_CONFIDENCE_TRACKER_H
#define PMAN_CONFIDENCE_TRACKER_H

#include "prediction_ledger.h"

struct ConfidenceMetrics {
    double cpuVariance;
    double thermalVariance;
    double latencyVariance;
};

class ConfidenceTracker {
public:
    // Updates running variance based on the latest error.
    // Uses Welford's online algorithm for numerical stability.
    void Observe(const PredictionError& error);

    // Accessor for current statistical state.
    ConfidenceMetrics GetMetrics() const;

    // Forcefully inject confidence (used by Investigator)
    void ForceConfidence(double amount);

private:
    struct RunningStat {
        double m_n = 0.0;
        double m_oldM = 0.0;
        double m_newM = 0.0;
        double m_oldS = 0.0;
        double m_newS = 0.0;

        void Push(double x);
        double Variance() const;
    };

    RunningStat m_cpuStat;
    RunningStat m_thermalStat;
    RunningStat m_latencyStat;
};

#endif // PMAN_CONFIDENCE_TRACKER_H
