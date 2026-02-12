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

#ifndef PMAN_TWEAKS_H
#define PMAN_TWEAKS_H

#include <windows.h>

// Core optimization functions
void IntelligentRamClean();
bool SetPrioritySeparation(DWORD val);
void SetHybridCoreAffinity(DWORD pid, int mode);
void SetAmd3DVCacheAffinity(DWORD pid, int mode);
BOOL SetProcessIoPriority(DWORD pid, int mode); // [FIX] Returns BOOL
void SetNetworkQoS(int mode);
void SetMemoryCompression(int mode);
void SetGpuPriority(DWORD pid, int mode);
void SetTimerResolution(int mode);
void SetProcessAffinity(DWORD pid, int mode);
void SetWorkingSetLimits(DWORD pid, int mode);
void OptimizeDpcIsrLatency(DWORD pid, int mode);
void CleanupProcessState(DWORD pid);
void SetTimerCoalescingControl(int mode);
void SetBackgroundPowerPolicy(DWORD pid, bool aggressive);

// Tiered Optimization (Tier 1: Core, Tier 2: Worker, Tier 3: Launcher)
void ApplyTieredOptimization(DWORD pid, int mode, bool isGameChild);

// Apply Anti-Bloat Registry Policies
void ApplyPrivacyPolicies();

// Memory pressure check
bool IsUnderMemoryPressure();

#endif // PMAN_TWEAKS_H
