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

#ifndef PMAN_AUTONOMOUS_ENGINE_H
#define PMAN_AUTONOMOUS_ENGINE_H

#include "types.h"

class AutonomousEngine {
public:
    AutonomousEngine()  = default;
    ~AutonomousEngine() = default;

    // Deleted copy/move — owned exclusively by PManContext::SubsystemState
    AutonomousEngine(const AutonomousEngine&)            = delete;
    AutonomousEngine& operator=(const AutonomousEngine&) = delete;

    // Called once during subsystem initialization in RunPMan(), after all
    // dependencies (telemetry, policy, budget, governor, evaluator, arbiter,
    // shadow, sandbox, intent, guard, confidence, ledger, provenance) are ready.
    void Init();

    // Executes one full SENSE->THINK->AUTHORIZE->ACT->LEARN cycle.
    // Called from the background WorkerQueue lambda in RunPMan().
    // Must be safe to call from any thread.
    void Tick();

    // Called during teardown in RunPMan(), after WorkerQueue::Stop() has
    // returned (guaranteeing no further Tick() calls are in flight).
    void Shutdown();

private:
    // Non-blocking snapshot read from background TelemetryAgent.
    // Mirrors the original file-static CaptureSnapshot() in main.cpp.
    SystemSignalSnapshot CaptureSnapshot() const;

    // Persistent state carried across ticks for OutcomeGuard evaluation.
    // Mirrors the original file-static g_lastPredicted / g_lastObserved.
    PredictedStateDelta m_lastPredicted{0, 0, 0};
    ObservedStateDelta  m_lastObserved{0, 0, 0};
};

#endif // PMAN_AUTONOMOUS_ENGINE_H
