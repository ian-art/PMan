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
#include <windows.h>
#include <cstdint>
#include <evntrace.h> // Required for EVENT_RECORD and TRACEHANDLE

class EtwMonitor {
public:
    // Main Thread Entry Point
    static void Run();
    
    // Control & Status
    static void Stop();
    static bool IsSessionActive();
    static uint64_t GetLastHeartbeat();
    
    // Recovery Logic (Called by Watchdog)
    static void CheckHealthAndRecover();

private:
    static void WINAPI EtwCallback(EVENT_RECORD* rec);
    static void WINAPI DpcIsrCallback(EVENT_RECORD* rec);
};
