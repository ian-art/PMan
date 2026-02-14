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

#ifndef PMAN_SYSINFO_H
#define PMAN_SYSINFO_H

#include <string>
#include <windows.h>
#include "types.h"

enum class AffinityStrategy {
    None,           // Don't touch affinity (Low core count)
    GameIsolation,  // Reserve cores for game (Homogeneous CPUs >= 4 cores)
    HybridPinning   // P/E core pinning (Intel 12th+ gen)
};

// Core detection functions
void DetectOSCapabilities();
void DetectHybridCoreSupport();
// Core Selection
DWORD_PTR GetOptimizationTargetCores(); 

bool DetectIoPrioritySupport();
bool DetectGameIoPrioritySupport();

AffinityStrategy GetRecommendedStrategy();

// Real-time System Metrics
double GetSystemCpuLoad();

#endif // PMAN_SYSINFO_H
