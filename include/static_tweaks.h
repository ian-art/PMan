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

#ifndef PMAN_STATIC_TWEAKS_H
#define PMAN_STATIC_TWEAKS_H

struct TweakConfig {
    bool network = true;      // TCP/IP, Throttling
    bool services = true;     // Manual Services
    bool privacy = true;      // Telemetry, Ads
    bool explorer = true;     // UI Visuals
    bool power = true;        // Power plans, Kernel
    bool location = true;     // Location services
    bool dvr = true;          // Xbox/GameBar
    bool bloatware = false;   // UWP Removal (Risk flagged)
};

// Executes the list of one-time system optimizations.
// Uses native Windows APIs to avoid AV detection (no cmd/reg.exe).
// Returns true if tweaks were applied, false if aborted.
bool ApplyStaticTweaks(const TweakConfig& config = TweakConfig());

#endif // PMAN_STATIC_TWEAKS_H
