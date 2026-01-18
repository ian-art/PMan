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

#include "nt_wrapper.h"

// Function Pointer Typedefs
typedef NTSTATUS (NTAPI *NtSetSystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtSetInformationProcess_t)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtSetInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtSetTimerResolution_t)(ULONG, BOOLEAN, PULONG);
typedef NTSTATUS (NTAPI *NtQueryTimerResolution_t)(PULONG, PULONG, PULONG);

// Static Pointers
static NtSetSystemInformation_t pNtSetSystemInformation = nullptr;
static NtQuerySystemInformation_t pNtQuerySystemInformation = nullptr;
static NtSetInformationProcess_t pNtSetInformationProcess = nullptr;
static NtSetInformationThread_t pNtSetInformationThread = nullptr;
static NtSetTimerResolution_t pNtSetTimerResolution = nullptr;
static NtQueryTimerResolution_t pNtQueryTimerResolution = nullptr;

bool NtWrapper::Initialize() {
    if (pNtSetSystemInformation) return true; // Already initialized

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return false;

    pNtSetSystemInformation = (NtSetSystemInformation_t)GetProcAddress(hNtDll, "NtSetSystemInformation");
    pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    pNtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hNtDll, "NtSetInformationProcess");
    pNtSetInformationThread = (NtSetInformationThread_t)GetProcAddress(hNtDll, "NtSetInformationThread");
    pNtSetTimerResolution = (NtSetTimerResolution_t)GetProcAddress(hNtDll, "NtSetTimerResolution");
    pNtQueryTimerResolution = (NtQueryTimerResolution_t)GetProcAddress(hNtDll, "NtQueryTimerResolution");

    return (pNtSetSystemInformation && pNtSetInformationProcess);
}

NTSTATUS NtWrapper::SetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length) {
    if (!Initialize() || !pNtSetSystemInformation) return (NTSTATUS)0xC0000002; // STATUS_NOT_IMPLEMENTED
    return pNtSetSystemInformation(InfoClass, Info, Length);
}

NTSTATUS NtWrapper::QuerySystemInformation(SYSTEM_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length, PULONG ReturnLength) {
    if (!Initialize() || !pNtQuerySystemInformation) return (NTSTATUS)0xC0000002;
    return pNtQuerySystemInformation(InfoClass, Info, Length, ReturnLength);
}

NTSTATUS NtWrapper::SetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS InfoClass, PVOID Info, ULONG Length) {
    if (!Initialize() || !pNtSetInformationProcess) return (NTSTATUS)0xC0000002;
    return pNtSetInformationProcess(ProcessHandle, InfoClass, Info, Length);
}

NTSTATUS NtWrapper::SetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS InfoClass, PVOID Info, ULONG Length) {
    if (!Initialize() || !pNtSetInformationThread) return (NTSTATUS)0xC0000002;
    return pNtSetInformationThread(ThreadHandle, InfoClass, Info, Length);
}

NTSTATUS NtWrapper::SetTimerResolution(ULONG DesiredTime, BOOLEAN SetResolution, PULONG ActualTime) {
    if (!Initialize() || !pNtSetTimerResolution) return (NTSTATUS)0xC0000002;
    return pNtSetTimerResolution(DesiredTime, SetResolution, ActualTime);
}

NTSTATUS NtWrapper::QueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime) {
    if (!Initialize() || !pNtQueryTimerResolution) return (NTSTATUS)0xC0000002;
    return pNtQueryTimerResolution(MaximumTime, MinimumTime, CurrentTime);
}
