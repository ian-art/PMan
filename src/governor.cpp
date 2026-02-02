/*
 * This file is part of Priority Manager (PMan).
 * Copyright (c) 2026 Ian Anthony R. Tancinco
 * Phase 2: Deterministic Performance Governor Implementation
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

// 5.4 Dominant Pressure Selector
DominantPressure PerformanceGovernor::SelectDominant(const NormalizedSignals& signals) {
    constexpr double CPU_THRESHOLD = 0.85;
    constexpr double MEM_THRESHOLD = 0.90;
    constexpr double DISK_THRESHOLD = 0.60;
    constexpr double LATENCY_THRESHOLD = 0.50;
    
    if (signals.latency > LATENCY_THRESHOLD) return DominantPressure::Latency;
    if (signals.memory > MEM_THRESHOLD) return DominantPressure::Memory;
    if (signals.disk > DISK_THRESHOLD) return DominantPressure::Disk;
    if (signals.cpu > CPU_THRESHOLD) return DominantPressure::Cpu;
    return DominantPressure::None;
}

// 5.5 System Mode Resolver
SystemMode PerformanceGovernor::ResolveMode(const NormalizedSignals& signals, bool userActive, bool thermal) {
    if (thermal) return SystemMode::ThermalRecovery;
    if (userActive) return SystemMode::Interactive;
    if (signals.cpu > 0.5 || signals.disk > 0.4) return SystemMode::SustainedLoad;
    return SystemMode::BackgroundMaintenance;
}

// 5.6 Allowed Intervention Class
AllowedActionClass PerformanceGovernor::DetermineActions(SystemMode mode, DominantPressure pressure) {
    if (mode == SystemMode::ThermalRecovery) return AllowedActionClass::ThermalSafety;
    
    if (mode == SystemMode::Interactive) {
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

// Section 6: Public API Implementation
GovernorDecision PerformanceGovernor::Decide(const SystemSignalSnapshot& snapshot) {
    GovernorDecision decision;
    
    // 1. Normalize
    NormalizedSignals sig = Normalize(snapshot);
    
    // 2. Identify Pressure
    decision.dominant = SelectDominant(sig);
    
    // 3. Resolve Mode
    decision.mode = ResolveMode(sig, snapshot.userActive, snapshot.isThermalThrottling);
    
    // 4. Gate Actions
    decision.allowedActions = DetermineActions(decision.mode, decision.dominant);
    
    return decision;
}
