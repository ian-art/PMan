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

#ifndef PMAN_INPUT_GUARDIAN_H
#define PMAN_INPUT_GUARDIAN_H

#include "types.h"
#include <atomic>
#include <mutex>

class InputGuardian {
public:
    void Initialize();
    void Shutdown();
    
    // Called from Main Loop on WM_INPUT
    void OnInput(DWORD msgTime);

    // Game Mode Integration
    void SetGameMode(bool enabled);

private:
    std::atomic<bool> m_active{false};
    DWORD m_dwmPid{0};
    
    // Input Interference Blocking
    HHOOK m_hKeyHook{nullptr};
    STICKYKEYS m_startupSticky{sizeof(STICKYKEYS), 0};
    TOGGLEKEYS m_startupToggle{sizeof(TOGGLEKEYS), 0};
    FILTERKEYS m_startupFilter{sizeof(FILTERKEYS), 0};
    bool m_blockingEnabled{false};

    void ToggleInterferenceBlocker(bool enable);
    
    // State Tracking
    DWORD m_lastForegroundTid{0};
    uint64_t m_lastBoostTime{0};
    uint64_t m_lastDwmScan{0};
    
    // Boost Logic
    void ApplyResponsivenessBoost();
    void BoostThread(DWORD tid, const char* debugTag);
    void BoostDwmProcess();
};

extern InputGuardian g_inputGuardian;

#endif // PMAN_INPUT_GUARDIAN_H
