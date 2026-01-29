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

namespace EditorManager {
    // Detects installed editors (Notepad++, VS Code, Sublime) and returns the best match
    std::wstring GetPreferredEditor();

    // Returns a display string for the menu (e.g., " [VS Code]")
    std::wstring GetEditorName();

    // Opens a file in the preferred editor, optionally jumping to a specific line
    // If 'forceAdmin' is true, it attempts to launch with elevated privileges (for ProgramData)
    void OpenFile(const std::wstring& filename, int jumpToLine = 0, bool forceAdmin = false);

    // Specific helper for locating section headers (e.g., "[games]") in the config
    void OpenConfigAtSection(const std::wstring& sectionName);
}
