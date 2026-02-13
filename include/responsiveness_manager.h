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

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mutex>
#include <string>
#include "types.h"

// --- Responsiveness Manager (Hung App Recovery) ---
class ResponsivenessManager {
    struct HungState {
        DWORD pid = 0;
        HWND hwnd = nullptr;
        uint64_t hangStartTime = 0;
        bool boosted = false;
        bool prompted = false;
        DWORD originalPriority = NORMAL_PRIORITY_CLASS;
        int originalThreadPriority = THREAD_PRIORITY_NORMAL;
        DWORD_PTR originalAffinity = 0;
    } m_state;

    std::mutex m_mtx;

    // Helper to write to Crash Recovery Ledger
    void UpdateLedger(DWORD pid, DWORD prio, DWORD_PTR affinity, bool active);

    void ApplySoftBoost(DWORD pid, DWORD tid);
    void Revert();
    void Reset();
    std::wstring GetProcessName(DWORD pid);

public:
    void Update();
};
