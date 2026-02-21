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
#include <filesystem> // [FIX] Required for dynamic path resolution

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup")

// --- Configuration ---
// [DYNAMIC] TARGET_EXE is resolved at runtime
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

// [PATCH] Shared Log Structure (Circular Buffer)
const size_t LOG_BUFFER_SIZE = 16384; // 16KB
const size_t LOG_BUFFER_MASK = LOG_BUFFER_SIZE - 1;

struct WatchdogLogShared {
    volatile LONG writeIndex;
    char buffer[LOG_BUFFER_SIZE];
};

// --- Global State ---
UniqueHandle g_hLogMap;
WatchdogLogShared* g_pLogShared = nullptr;
UniqueHandle g_hMapFile;
UniqueView g_pHeartbeatView;
HeartbeatSharedMemory* g_pHeartbeat = nullptr;
UniqueHandle g_hTargetProcess;

void InitLogShared() {
    g_hLogMap.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(WatchdogLogShared), L"Local\\PManWatchdogLog"));
    if (g_hLogMap) {
        g_pLogShared = (WatchdogLogShared*)MapViewOfFile(g_hLogMap.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (g_pLogShared) {
            // Only zero if we just created it (check GetLastError for ERROR_ALREADY_EXISTS if needed, 
            // but for watchdog restarts, we might want to keep history. simpler to just clear on fresh start.)
            // For now, we assume ephemeral per-session logging.
        }
    }
}

void Log(const wchar_t* msg) {
    SYSTEMTIME st; GetLocalTime(&st);
    
    // 1. Console Output
    wprintf(L"[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);

    // 2. Shared Memory Broadcast
    if (g_pLogShared) {
        char buf[512];
        // Format as UTF-8 for compact storage (%S handles wchar_t conversion)
        int len = sprintf_s(buf, "[%02d:%02d:%02d] %S\n", st.wHour, st.wMinute, st.wSecond, msg);
        if (len > 0) {
            for (int i = 0; i < len; i++) {
                LONG idx = InterlockedIncrement(&g_pLogShared->writeIndex) - 1;
                g_pLogShared->buffer[idx & LOG_BUFFER_MASK] = buf[i];
            }
        }
    }
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
    Log(L"Launching Core...");
    
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    // [DYNAMIC] Derive target executable name from Watchdog's own name
    // Convention: If named "AppNameWatchdog.exe", target is "AppName.exe"
    std::filesystem::path self(selfPath);
    std::wstring stem = self.stem().wstring();
    std::wstring targetName = L"PMan.exe"; // Fallback default

    std::wstring suffix = L"Watchdog";
    // Case-insensitive suffix check
    if (stem.length() > suffix.length() && 
        _wcsicmp(stem.substr(stem.length() - suffix.length()).c_str(), suffix.c_str()) == 0) {
        targetName = stem.substr(0, stem.length() - suffix.length()) + L".exe";
    }

    std::wstring targetPath = (self.parent_path() / targetName).wstring();
    std::wstring targetDir = self.parent_path().wstring();

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

    // [PATCH] Set explicit working directory to prevent UAC "Run as Admin" 
    // from defaulting to C:\Windows\System32, which breaks relative icon paths.
    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 0, NULL, targetDir.c_str(), &si, &pi)) {
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

static std::wstring GetTargetExePath() {
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::filesystem::path self(selfPath);
    std::wstring stem = self.stem().wstring();
    std::wstring targetName = L"PMan.exe";
    const std::wstring suffix = L"Watchdog";
    if (stem.length() > suffix.length() &&
        _wcsicmp(stem.substr(stem.length() - suffix.length()).c_str(), suffix.c_str()) == 0) {
        targetName = stem.substr(0, stem.length() - suffix.length()) + L".exe";
    }
    return (self.parent_path() / targetName).wstring();
}

static std::wstring GetPManVersionString() {
    const std::wstring path = GetTargetExePath();
    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return L"Unknown";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), handle, size, data.data())) return L"Unknown";
    VS_FIXEDFILEINFO* pInfo = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&pInfo), &len) || len == 0) return L"Unknown";
    wchar_t ver[64];
    StringCchPrintfW(ver, 64, L"%u.%u.%u.%u",
        HIWORD(pInfo->dwFileVersionMS), LOWORD(pInfo->dwFileVersionMS),
        HIWORD(pInfo->dwFileVersionLS), LOWORD(pInfo->dwFileVersionLS));
    return ver;
}

// [FIX] Use wWinMain to run in background (no console window)
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitLogShared(); // [PATCH] Initialize Logging Channel
    Log(L"Watchdog Started.");

    // [FIX] Capture raw arguments for restart logic
    std::wstring forwardArgs = lpCmdLine;

    // Initial Launch with arguments
    LaunchTarget(forwardArgs.c_str());

    uint64_t lastSeenCounter = 0;
    uint64_t lastChangeTime = GetTickCount64();

    while (true) {
        Sleep(CHECK_INTERVAL_MS);

        // 1. Check if Process is Alive (Kernel Object)
        DWORD exitCode = 0;
        if (g_hTargetProcess == NULL || !GetExitCodeProcess(g_hTargetProcess.get(), &exitCode) || exitCode != STILL_ACTIVE) {
            
            // [LOGIC] Respect Graceful Exit (User initiated quit)
            if (exitCode == 0) {
                Log(L"Core exited gracefully (Code 0). Watchdog shutting down.");
                return 0;
            }

            Log(L"Core process termination detected (Crash/Kill).");
            
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
            if (crashCount >= 2) {
                std::wstring msg = L"PMan has crashed and failed to recover on the second launch.\n\n"
                    L"Please send the following to the developer:\n"
                    L"  \u2022 Dump file(s) located in:\n"
                    L"    C:\\ProgramData\\PriorityMgr\\Dumps\n\n"
                    L"  \u2022 PMan Version: ";
                msg += GetPManVersionString();
                msg += L"\n\nThe Watchdog will now exit.";
                Log(L"[CRITICAL] PMan failed on second launch. Notifying user and exiting.");
                MessageBoxW(nullptr, msg.c_str(), L"PMan - Critical Failure", MB_OK | MB_ICONERROR);
                return 0;
            }
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
