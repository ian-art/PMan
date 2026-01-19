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
#include <string>
#include <vector>
#include <filesystem>

#ifndef PMAN_RESTORE_H
#define PMAN_RESTORE_H

// -- Registry Transaction Structure --
struct RegistryBackupState {
    // Core System
    DWORD prioritySeparation = 0xFFFFFFFF;
    DWORD networkThrottling = 0xFFFFFFFF;
    DWORD coalescingTimer = 0xFFFFFFFF;
    DWORD memoryCompression = 0xFFFFFFFF;
    
    // Multimedia & Games
    DWORD systemResponsiveness = 0xFFFFFFFF;
    DWORD gpuPriority = 0xFFFFFFFF;
    DWORD gamesPriority = 0xFFFFFFFF;
    wchar_t schedulingCategory[32] = {0}; // String value
    wchar_t sfioPriority[32] = {0};       // String value

    // Memory & Kernel
    DWORD largeSystemCache = 0xFFFFFFFF;
    DWORD distributeTimers = 0xFFFFFFFF;
    DWORD disablePagingExecutive = 0xFFFFFFFF;
    DWORD lanmanServerSize = 0xFFFFFFFF;

    // GameDVR & FSE
    DWORD gameDvrEnabled = 0xFFFFFFFF;
    DWORD gameDvrFseBehavior = 0xFFFFFFFF;
    DWORD gameDvrHonorUserFse = 0xFFFFFFFF;
    DWORD gameDvrDxgiHonorFse = 0xFFFFFFFF;
    DWORD appCaptureEnabled = 0xFFFFFFFF; // HKCU
    DWORD allowGameDvrPolicy = 0xFFFFFFFF; // Policy

    // Power
    wchar_t powerSchemeGuid[64] = {0}; 
    
    bool isValid = false;
};

// Checks if a restore point has been created for this version/installation.
// If not, attempts to create one and marks the flag in the registry.
void EnsureStartupRestorePoint();

// Manually attempts to create a named System Restore point.
// Returns true if successful or if the request was accepted by the OS.
bool CreateRestorePoint();

// Crash-Proof Watchdog (Main Entry Point)
// Now pulls extended state from pman_restore.bin if available
void RunRegistryGuard(DWORD targetPid, DWORD lowTime, DWORD highTime, DWORD originalVal, const std::wstring& startupPowerScheme);

// Internal Helper: Launch the watchdog process (Saves state to disk first)
void LaunchRegistryGuard(DWORD originalVal);

// Internal helpers used by restore/guard
std::filesystem::path GetStateFilePath();
DWORD ReadRegDWORD(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName);

#endif // PMAN_RESTORE_H