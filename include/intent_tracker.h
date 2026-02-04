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

#ifndef PMAN_INTENT_TRACKER_H
#define PMAN_INTENT_TRACKER_H

#include "types.h"
#include <cstdint>

struct IntentState {
    BrainAction lastAction;
    uint32_t consecutiveCount;
};

class IntentTracker {
public:
    IntentTracker();

    // Updates the tracker with the latest proposed action.
    void Observe(BrainAction proposed);

    // Checks if the current intent has been consistent for the required number of ticks.
    // N = Consecutive Ticks
    bool IsStable(uint32_t requiredTicks) const;

    // Accessors for Logging
    uint32_t GetCount() const;
    bool WasReset() const;
    BrainAction GetCurrentIntent() const;

private:
    IntentState m_state;
    bool m_wasReset; // Transient flag for the current tick's logging
};

#endif // PMAN_INTENT_TRACKER_H
