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
 
#include "context.h"
#include "services.h"
#include "performance.h"
#include "explorer_booster.h"
#include "idle_affinity.h"
#include "memory_optimizer.h"
#include "input_guardian.h"

// Constructor: Initialize Subsystems
PManContext::PManContext() {
    subs.serviceMgr = std::make_unique<WindowsServiceManager>();
    subs.perf       = std::make_unique<PerformanceGuardian>();
    subs.explorer   = std::make_unique<ExplorerBooster>();
    subs.idle       = std::make_unique<IdleAffinityManager>();
    subs.mem        = std::make_unique<MemoryOptimizer>();
    subs.input      = std::make_unique<InputGuardian>();
}

// Destructor: Default (Required for unique_ptr with forward declared types)
PManContext::~PManContext() = default;

