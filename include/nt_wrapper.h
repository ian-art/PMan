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

#ifndef PMAN_NT_WRAPPER_H
#define PMAN_NT_WRAPPER_H

#include <windows.h>
#include <winternl.h>

// Enums and Structs missing from standard headers
#ifndef SystemMemoryListInformation
#define SystemMemoryListInformation (SYSTEM_INFORMATION_CLASS)80
#endif

// IO Priority Constants
#ifndef IoPriorityVeryLow
#define IoPriorityVeryLow 0
#endif
#ifndef IoPriorityLow
#define IoPriorityLow 1
#endif
#ifndef IoPriorityVeryLow
#define IoPriorityVeryLow 0
#endif
#ifndef IoPriorityLow
#define IoPriorityLow 1
#endif
#ifndef IoPriorityNormal
#define IoPriorityNormal 2
#endif
#ifndef IoPriorityHigh
#define IoPriorityHigh 3
#endif
#ifndef IoPriorityCritical
#define IoPriorityCritical 4
#endif

// Power Throttling
#ifndef ProcessPowerThrottling
#define ProcessPowerThrottling (PROCESS_INFORMATION_CLASS)62
#endif

// Check if SDK already defines this (via the Version constant)
#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
typedef struct _PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
} PROCESS_POWER_THROTTLING_STATE, *PPROCESS_POWER_THROTTLING_STATE;

#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#define PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION 0x4
#endif

// Timer Resolution
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

class NtWrapper {
public:
    static bool Initialize();

    // System Information
    static NTSTATUS SetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length);
    static NTSTATUS QuerySystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length, PULONG ReturnLength);

    // Process & Thread Information
    static NTSTATUS SetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length);
    static NTSTATUS SetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS InfoClass, PVOID Info, ULONG Length);

    // Timer Resolution
    static NTSTATUS SetTimerResolution(ULONG DesiredTime, BOOLEAN SetResolution, PULONG ActualTime);
    static NTSTATUS QueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime);

    // Generic Helper
    static void* GetProcAddress(const char* procName);
};

#endif // PMAN_NT_WRAPPER_H
