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

#ifndef PMAN_CONTEXT_H
#define PMAN_CONTEXT_H

#include <atomic>
#include <mutex>
#include "types.h"

class PManContext {
public:
    static PManContext& Get() {
        static PManContext instance;
        return instance;
    }

    // Delete copy/move to enforce singleton
    PManContext(const PManContext&) = delete;
    PManContext& operator=(const PManContext&) = delete;

    // -- State Variables --
    std::atomic<bool> isRunning{true};
    std::atomic<bool> isPaused{false};
    std::atomic<bool> isSuspended{false}; // System sleep/hibernate state
    std::atomic<bool> servicesSuspended{false};
    std::atomic<bool> reloadRequested{false};

    // -- Configuration State --
    std::atomic<bool> ignoreNonInteractive{true};
    std::atomic<bool> restoreOnExit{true};
    
    // -- Session State --
    std::atomic<DWORD> lastGamePid{0};
    std::atomic<int>   lastMode{0};

private:
    PManContext() = default;
};

#endif // PMAN_CONTEXT_H