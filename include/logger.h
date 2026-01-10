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

#ifndef PMAN_LOGGER_H
#define PMAN_LOGGER_H

#include <string>
#include <filesystem>

// Log a message to the internal circular buffer
void Log(const std::string& msg);

// Get the path to the log directory
std::filesystem::path GetLogPath();

// Telemetry-Safe Logging Control
void InitLogger();     // Initialize buffer and directory
void ShutdownLogger(); // Flush buffer to disk and close
void FlushLogger();    // Force write buffer to disk (used by Viewer)

#endif // PMAN_LOGGER_H
