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

#ifndef PMAN_GUI_MANAGER_H
#define PMAN_GUI_MANAGER_H

#include <windows.h>

namespace GuiManager {
    // Initializes resources (if needed) and shows the configuration window.
    // Safe to call repeatedly (will just focus the existing window).
    void ShowTuneUpWindow();

    // Returns true if the GUI window is currently open.
    // Use this to determine if you should call RenderFrame().
    bool IsWindowOpen();

    // Renders one frame of the GUI.
    // Must be called inside the main application loop when IsWindowOpen() is true.
    void RenderFrame();

    // Cleans up DirectX and ImGui resources.
    void Shutdown();
}

#endif // PMAN_GUI_MANAGER_H
