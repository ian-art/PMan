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

#include "intent_tracker.h"
#include "context.h"

IntentTracker::IntentTracker() {
    m_state.lastAction = BrainAction::Maintain;
    m_state.consecutiveCount = 0;
    m_wasReset = false;
}

void IntentTracker::Observe(BrainAction proposed) {
    if (proposed == m_state.lastAction) {
        // Increment count, preventing overflow
        if (m_state.consecutiveCount < UINT32_MAX) {
            m_state.consecutiveCount++;
        }
        m_wasReset = false;
    } else {
        // Change detected: Reset count
        m_state.lastAction = proposed;
        m_state.consecutiveCount = 1; // Start at 1 (this is the first tick of new intent)
        m_wasReset = true;
    }
}

bool IntentTracker::IsStable(uint32_t requiredTicks) const {
    // [FAULT INJECTION]
    if (PManContext::Get().fault.intentInvalid) {
        return false;
    }

    if (requiredTicks == 0) return true;
    return m_state.consecutiveCount >= requiredTicks;
}

uint32_t IntentTracker::GetCount() const {
    return m_state.consecutiveCount;
}

bool IntentTracker::WasReset() const {
    return m_wasReset;
}

BrainAction IntentTracker::GetCurrentIntent() const {
    return m_state.lastAction;
}
