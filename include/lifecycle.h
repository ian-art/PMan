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
#include <string>

namespace Lifecycle {
    // Terminates other running instances of this executable (used during uninstall/update)
    void TerminateExistingInstances();

    // Checks if the Scheduled Task exists
    bool IsTaskInstalled(const std::wstring& taskName);

    // Returns: 0 = Disabled, 1 = Active, 2 = Passive (Paused)
    int GetStartupMode(const std::wstring& taskName);

    // Creates the Scheduled Task (Silent by default, optionally paused)
    // Returns true if successful
    bool InstallTask(const std::wstring& taskName, const std::wstring& exePath, bool passiveMode);

    // Removes the Scheduled Task
    void UninstallTask(const std::wstring& taskName);
}
