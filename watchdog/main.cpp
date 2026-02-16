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

/*
 * PMan Watchdog
 * The "Gold Standard" for reliability.
 *
 * Responsibilities:
 * 1. Monitors PMan.exe via Heartbeat (Shared Memory).
 * 2. Detects hangs/freezes (not just crashes).
 * 3. Generates Minidumps from OUTSIDE the crashed process.
 * 4. Restarts PMan.exe automatically.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <strsafe.h>
#include <atomic>
#include <string>
#include <iostream>
#include <tlhelp32.h>
#include <vector> // [FIX] Required for std::vector
#include <memory> // [FIX] Required for std::unique_ptr

#pragma comment(lib, "Dbghelp.lib")

// --- Configuration ---
const wchar_t* TARGET_EXE = L"PMan.exe";
// [HIGH PRIORITY] Dump Storm Protection
const int MAX_RESTARTS = 5;       // Max restarts...
const int STORM_WINDOW_MS = 60000; // ...in 60 seconds
const int RESTART_DELAY_MS = 2000; // [HIGH PRIORITY] Backoff delay

// [MEDIUM PRIORITY] RAII Handles
struct HandleDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

struct ViewDeleter {
    void operator()(void* p) const {
        if (p) UnmapViewOfFile(p);
    }
};
using UniqueView = std::unique_ptr<void, ViewDeleter>;
const wchar_t* DUMP_FOLDER = L"C:\\ProgramData\\PriorityMgr\\Dumps";
const DWORD HEARTBEAT_TIMEOUT_MS = 30000; // 30 seconds without pulse = Hang
const DWORD CHECK_INTERVAL_MS = 1000;

// --- Shared Memory Structure (Must match PMan) ---
struct HeartbeatSharedMemory {
    std::atomic<uint64_t> counter;  // Monotonic increment
    uint64_t last_tick;             // System tick at update
    DWORD pid;                      // Target Process ID
};

// --- Global State ---
UniqueHandle g_hMapFile;
UniqueView g_pHeartbeatView;
HeartbeatSharedMemory* g_pHeartbeat = nullptr;
UniqueHandle g_hTargetProcess;

void Log(const wchar_t* msg) {
    // Simple console logging for watchdog
    SYSTEMTIME st; GetLocalTime(&st);
    wprintf(L"[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);
}

// Write dump of the target process (External Dump)
void WriteExternalDump(DWORD pid, HANDLE hProcess) {
    wchar_t path[MAX_PATH];
    SYSTEMTIME st; GetLocalTime(&st);
    
    CreateDirectoryW(DUMP_FOLDER, nullptr);
    StringCchPrintfW(path, MAX_PATH, L"%s\\PMan_Hang_%04d%02d%02d_%02d%02d%02d.dmp",
        DUMP_FOLDER, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    Log(L"Writing Hang Dump...");
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD flags = MiniDumpWithIndirectlyReferencedMemory |
                      MiniDumpScanMemory |
                      MiniDumpWithThreadInfo |
                      MiniDumpWithUnloadedModules;

        // Note: We cannot easily capture the remote exception info for a hang,
        // so we pass NULL for ExceptionParam. This creates a snapshot dump.
        BOOL success = MiniDumpWriteDump(
            hProcess,
            pid,
            hFile,
            (MINIDUMP_TYPE)flags,
            nullptr, // No exception info for hangs
            nullptr, // No user stream (breadcrumbs difficult to read externally without parsing)
            nullptr
        );

        if (success) Log(L"Dump written successfully.");
        else Log(L"Failed to write dump.");
        
        CloseHandle(hFile);
    }
}

// Argument Forwarding
// We capture the raw command line to pass flags like --paused or /silent
void LaunchTarget(const wchar_t* args = nullptr) {
    Log(L"Launching PMan...");
    
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    std::wstring targetPath = std::wstring(selfPath);
    
    // Strip "PManWatchdog.exe" and replace with "PMan.exe"
    size_t pos = targetPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        targetPath = targetPath.substr(0, pos + 1) + TARGET_EXE;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Prepare command line (Target + Args)
    std::wstring cmdLine = L"\"" + targetPath + L"\"";
    if (args && *args) {
        cmdLine += L" ";
        cmdLine += args;
    }

    // Pass mutable string to CreateProcess
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 0, NULL, NULL, &si, &pi)) {
        // [MEDIUM PRIORITY] Transfer ownership to RAII handle
        g_hTargetProcess.reset(pi.hProcess);
        CloseHandle(pi.hThread); // We don't need the thread handle
        Log(L"PMan launched.");
    } else {
        Log(L"Failed to launch PMan.");
        Sleep(5000); // Wait before retry
    }
}

bool ConnectToSharedMemory() {
    if (g_pHeartbeat) return true;

    // Try to open the mapping created by PMan
    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Local\\PManHeartbeat");
    
    if (hMap) {
        g_hMapFile.reset(hMap); // Take ownership
        
        void* pView = MapViewOfFile(g_hMapFile.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(HeartbeatSharedMemory));
        if (pView) {
            g_pHeartbeatView.reset(pView); // Take ownership
            g_pHeartbeat = static_cast<HeartbeatSharedMemory*>(pView);
            Log(L"Connected to PMan Heartbeat.");
            return true;
        }
    }
    return false;
}

// Use wmain to capture arguments
int wmain(int argc, wchar_t* argv[]) {
    Log(L"Watchdog Started.");

    // Reconstruct arguments to forward (skip argv[0] which is watchdog exe)
    std::wstring forwardArgs = L"";
    for (int i = 1; i < argc; i++) {
        forwardArgs += argv[i];
        if (i < argc - 1) forwardArgs += L" ";
    }

    // Initial Launch with arguments
    LaunchTarget(forwardArgs.c_str());

    uint64_t lastSeenCounter = 0;
    uint64_t lastChangeTime = GetTickCount64();

    while (true) {
        Sleep(CHECK_INTERVAL_MS);

        // 1. Check if Process is Alive (Kernel Object)
        DWORD exitCode = 0;
        if (g_hTargetProcess == NULL || !GetExitCodeProcess(g_hTargetProcess, &exitCode) || exitCode != STILL_ACTIVE) {
            Log(L"PMan process termination detected.");
            
            // [MEDIUM PRIORITY] RAII Cleanup (Automatic reset)
            g_hTargetProcess.reset();
            g_pHeartbeat = nullptr;
            g_pHeartbeatView.reset(); // Unmaps view
            g_hMapFile.reset();       // Closes handle

            // [HIGH PRIORITY] Dump Storm Protection
            uint64_t now = GetTickCount64();
            static uint64_t windowStart = now;
            static int crashCount = 0;

            if (now - windowStart > STORM_WINDOW_MS) {
                // Window passed, reset counter
                windowStart = now;
                crashCount = 0;
            }

            crashCount++;
            if (crashCount > MAX_RESTARTS) {
                Log(L"[CRITICAL] Dump Storm Detected (Too many crashes). Aborting restart to protect system.");
                return 1; // Exit Watchdog
            }

            // [HIGH PRIORITY] Restart Backoff
            Log(L"Waiting before restart...");
            Sleep(RESTART_DELAY_MS);

            // Restart
            LaunchTarget(forwardArgs.c_str());
            lastChangeTime = GetTickCount64(); // Reset timer
            continue;
        }

        // 2. Check Heartbeat (Hang Detection)
        if (ConnectToSharedMemory()) {
            uint64_t currentCounter = g_pHeartbeat->counter.load(std::memory_order_relaxed);
            
            if (currentCounter != lastSeenCounter) {
                // It's alive and ticking
                lastSeenCounter = currentCounter;
                lastChangeTime = GetTickCount64();
            } else {
                // Counter hasn't moved. Check timeout.
                if (GetTickCount64() - lastChangeTime > HEARTBEAT_TIMEOUT_MS) {
                    Log(L"PMan HANG DETECTED (Heartbeat stalled).");
                    
                    // Generate Hang Dump
                    WriteExternalDump(g_pHeartbeat->pid, g_hTargetProcess.get());

                    // Terminate and Restart
                    Log(L"Terminating frozen process...");
                    TerminateProcess(g_hTargetProcess.get(), 0xDEAD);
                    
                    // Loop will catch termination in next iteration and restart
                }
            }
        }
    }

    return 0;
}
