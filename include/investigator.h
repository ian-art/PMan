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

#ifndef PMAN_INVESTIGATOR_H
#define PMAN_INVESTIGATOR_H

#include "types.h"
#include <vector>
#include <future> // [PATCH] Async Support

enum class DiagnosisType {
    None,
    FalseAlarm_Aliasing,   // CPU was pulsing, not sustained
    TruePressure_Sustained,// Real load confirmed
    Process_Deadlocked,    // App is hung, not busy
    IO_Thrashing,          // Disk is random-seeking (Danger)
    External_Interference  // User/OS undid our change
};

struct InvestigationVerdict {
    bool resolved;
    DiagnosisType type;
    double confidenceBoost; // +0.0 to +1.0
    bool recommendVeto;     // Stop the proposed action?
};

class Investigator {
public:
    Investigator();
    ~Investigator() = default;

    // Main Entry Point
    // Called by DecisionArbiter when confidence is low or consequences are unsafe.
    InvestigationVerdict Diagnose(const GovernorDecision& govState);

    // [PATCH] Async Diagnosis (Non-blocking)
    // Launches diagnosis in a background thread to prevent stalling the Decision Loop.
    std::future<InvestigationVerdict> DiagnoseAsync(const GovernorDecision& govState);

private:
    // Signal De-Noiser
    DiagnosisType PerformCpuMicroBurst();

    // Wait Chain Traversal
    DiagnosisType ProbeWaitChain(DWORD pid);

    // Disk Pattern Analyst
    DiagnosisType ProbeDiskThrashing(DWORD pid);

    // Process Forensics (Responsiveness & Intent)
    DiagnosisType ProbeHungWindow(DWORD pid);
    DiagnosisType ProbeWorkloadChange(DWORD pid, DWORD baselineThreadCount);
    
    // Internal constants
    static constexpr int MICRO_BURST_SAMPLES = 10;
    static constexpr int MICRO_BURST_DURATION_MS = 50;
    static constexpr int BURST_INTERVAL_MS = 5;
};

#endif // PMAN_INVESTIGATOR_H
