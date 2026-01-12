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

#ifndef PMAN_SERVICES_WATCHER_H
#define PMAN_SERVICES_WATCHER_H

#include <string>
#include <vector>
#include <windows.h>
#include <unordered_set>

class ServiceWatcher {
public:
    static void Initialize();
    static void OnTick();

private:
    static void ScanAndTrimManualServices();
    
    static bool IsServiceRunningAndIdle(const std::wstring& serviceName);
    static bool IsProcessIdle(DWORD pid);
    
    // Safety check to prevent killing Audio/Network/Drivers
    static bool IsSafeToStop(const std::wstring& serviceName);
};

#endif // PMAN_SERVICES_WATCHER_H
