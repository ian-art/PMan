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

#include "governor.h"
#include <algorithm>

// 5.2 Normalized Signals
PerformanceGovernor::NormalizedSignals PerformanceGovernor::Normalize(const SystemSignalSnapshot& raw) {
    NormalizedSignals sig;
    sig.cpu = std::clamp(raw.cpuLoad / 100.0, 0.0, 1.0);
    sig.memory = std::clamp(raw.memoryPressure / 100.0, 0.0, 1.0);
    sig.disk = std::clamp(raw.diskQueueLen / 5.0, 0.0, 1.0);
    if (raw.latencyMs <= 10.0) sig.latency = 0.0;
    else sig.latency = std::clamp((raw.latencyMs - 10.0) / 90.0, 0.0, 1.0);
    return sig;
}

// Policy Injection
void PerformanceGovernor::UpdatePolicy(const PolicyParameters& params) {
    m_params = params;
}

// 5.4 Dominant Pressure Selector
DominantPressure PerformanceGovernor::SelectDominant(const NormalizedSignals& signals) {
    // Use tunable parameters instead of constants
    if (signals.latency > m_params.latencyThreshold) return DominantPressure::Latency;
    if (signals.memory > m_params.memThreshold) return DominantPressure::Memory;
    if (signals.disk > m_params.diskThreshold) return DominantPressure::Disk;
    if (signals.cpu > m_params.cpuThreshold) return DominantPressure::Cpu;
    return DominantPressure::None;
}

// 5.5 System Mode Resolver
SystemMode PerformanceGovernor::ResolveMode(const NormalizedSignals& signals, bool userActive, bool thermal, bool security) {
    if (thermal) return SystemMode::ThermalRecovery;
    
    // [DCM] Security Co-existence Logic
    // If user is active BUT security software is hammering the system,
    // we enter a special Interactive sub-state (handled by DominantPressure::Security later)
    // For now, we force Interactive to ensure we prioritize the user.
    if (userActive) return SystemMode::Interactive;
    
    // If not active, but AV is scanning, treat as Maintenance
    if (security) return SystemMode::BackgroundMaintenance;

    if (signals.cpu > 0.5 || signals.disk > 0.4) return SystemMode::SustainedLoad;
    return SystemMode::BackgroundMaintenance;
}

// 5.6 Allowed Intervention Class
AllowedActionClass PerformanceGovernor::DetermineActions(SystemMode mode, DominantPressure pressure) {
    if (mode == SystemMode::ThermalRecovery) return AllowedActionClass::ThermalSafety;
    
    if (mode == SystemMode::Interactive) {
        // [DCM] If Security Pressure is the dominant factor during interaction,
        // we authorize the Foreground Shield (SecurityMitigation)
        if (pressure == DominantPressure::Security) return AllowedActionClass::SecurityMitigation;

        if (pressure == DominantPressure::None) return AllowedActionClass::None;
        if (pressure == DominantPressure::Latency || pressure == DominantPressure::Cpu) return AllowedActionClass::Scheduling;
        if (pressure == DominantPressure::Disk) return AllowedActionClass::IoPrioritization;
    }
    
    if (mode == SystemMode::SustainedLoad) {
        if (pressure == DominantPressure::Disk) return AllowedActionClass::IoPrioritization;
        if (pressure == DominantPressure::Memory) return AllowedActionClass::MemoryReclaim;
    }
    
    if (mode == SystemMode::BackgroundMaintenance) return AllowedActionClass::MemoryReclaim;
    return AllowedActionClass::None;
}

// Public API Implementation
GovernorDecision PerformanceGovernor::Decide(const SystemSignalSnapshot& snapshot) {
    GovernorDecision decision;
    
    // 1. Normalize
    NormalizedSignals sig = Normalize(snapshot);
    
    // 2. Identify Pressure
    decision.dominant = SelectDominant(sig);

    // [DCM] Override Dominant Pressure if Security Signal is High
    // We treat Security Pressure as a "Super-Dominant" factor that overrides normal resource pressure
    // because fighting AV IO is futile; we must shield instead.
    if (snapshot.isSecurityPressure) {
        decision.dominant = DominantPressure::Security; // Requires DominantPressure::Security in Types.h
    }
    
    // 3. Resolve Mode
    decision.mode = ResolveMode(sig, snapshot.userActive, snapshot.isThermalThrottling, snapshot.isSecurityPressure);
    
    // 4. Gate Actions
    decision.allowedActions = DetermineActions(decision.mode, decision.dominant);
    
    return decision;
}
