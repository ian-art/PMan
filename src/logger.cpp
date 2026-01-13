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

#include "logger.h"
#include "constants.h" // Required for WM_LOG_UPDATED
#include "types.h"
#include "utils.h"     // Required for GetCurrentExeVersion
#include <windows.h>
#include <sddl.h>   // Required for security descriptor string conversion
#include <aclapi.h> // Required for security functions
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <deque>
#include <atomic>

// Circular Buffer Settings
static const size_t MAX_LOG_HISTORY = 2000; // Keep last 2000 lines in RAM
static std::deque<std::string> g_logBuffer;
static std::mutex g_logMtx;
static std::atomic<bool> g_loggerInitialized{false};

std::filesystem::path GetLogPath()
{
    wchar_t* programData = nullptr;
    size_t len = 0;
    if (_wdupenv_s(&programData, &len, L"ProgramData") == 0 && programData)
    {
        std::filesystem::path result = std::filesystem::path(programData) / L"PriorityMgr";
        free(programData);
        return result;
    }
    return std::filesystem::path(L"C:\\ProgramData\\PriorityMgr");
}

// Ensure Log Directory exists with correct permissions
static void EnsureLogDirectory()
{
    std::filesystem::path dir = GetLogPath();
    if (!std::filesystem::exists(dir))
    {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        // D:DACL, A:Allow, GA:GenericAll (Admins), GR:GenericRead (Users)
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;OICI;GA;;;BA)(A;OICI;GR;;;BU)", 
                SDDL_REVISION_1, &pSD, nullptr))
        {
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
            CreateDirectoryW(dir.c_str(), &sa);
            LocalFree(pSD);
        }
        else
        {
            std::filesystem::create_directories(dir);
        }
    }
}

void FlushLogger()
{
    std::lock_guard lg(g_logMtx);
    if (g_logBuffer.empty()) return;

    try
    {
        std::filesystem::path dir = GetLogPath();
        auto logPath = dir / L"log.txt";

        // Rotate if too big (>5MB)
        if (std::filesystem::exists(logPath) && std::filesystem::file_size(logPath) > 5 * 1024 * 1024) {
            auto backupPath = dir / L"log.old.txt";
            std::filesystem::copy_file(logPath, backupPath, std::filesystem::copy_options::overwrite_existing);
            std::filesystem::resize_file(logPath, 0); 
        }

        std::ofstream log(logPath, std::ios::app);
        if (log)
        {
            for (const auto& line : g_logBuffer) {
                log << line << "\n";
            }
            g_logBuffer.clear();
        }
    }
    catch (...) {
        // Disk I/O errors are suppressed in release build to prevent crashes
    }
}

void InitLogger()
{
    EnsureLogDirectory();

    // Rotate logs on startup: log.txt -> log.pman_<version>.txt
    try {
        std::filesystem::path dir = GetLogPath();
        std::filesystem::path logFile = dir / L"log.txt";

        if (std::filesystem::exists(logFile)) {
            // Append version to filename for better history tracking
            std::wstring ver = GetCurrentExeVersion();

            // Generate Timestamp
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            char timeBuf[64] = {0};
            std::wstring wTime;

            if (localtime_s(&timeinfo, &t) == 0) {
                 if (std::strftime(timeBuf, sizeof(timeBuf), "_%Y-%m-%d_%H-%M-%S", &timeinfo)) {
                     std::string sTime(timeBuf);
                     wTime.assign(sTime.begin(), sTime.end());
                 }
            }

            std::wstring backupName = L"log.pman_" + ver + wTime + L".txt";
            std::filesystem::path bakFile = dir / backupName;

            // Remove existing file if present (Unlikely with timestamp, but safe to keep)
            if (std::filesystem::exists(bakFile)) {
                std::filesystem::remove(bakFile);
            }
            std::filesystem::rename(logFile, bakFile);
        }
    } catch (...) {
        // Ignore file access errors (e.g. if log is currently locked)
    }

    g_loggerInitialized = true;
    Log("--- Logger Initialized (Circular Buffer Mode) ---");
}

void ShutdownLogger()
{
    if (g_loggerInitialized) {
        Log("--- Logger Shutdown (Flushing to disk) ---");
        FlushLogger();
        g_loggerInitialized = false;
    }
}

void Log(const std::string& msg)
{
    // Format timestamp
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timebuf[32] = {0};
    struct tm timeinfo;
    
    std::string formattedMsg;
    if (localtime_s(&timeinfo, &t) == 0 && std::strftime(timebuf, 32, "%Y-%m-%d %H:%M:%S", &timeinfo) > 0)
    {
        formattedMsg = std::string(timebuf) + "  " + msg;
    }
    else
    {
        formattedMsg = msg;
    }

    // Write to Circular Buffer
    {
        std::lock_guard lg(g_logMtx);
        g_logBuffer.push_back(formattedMsg);
        if (g_logBuffer.size() > MAX_LOG_HISTORY) {
            g_logBuffer.pop_front();
        }
    }

    // Telemetry Safety
    // Only flush to disk if the Log Viewer is actually open (Debugging Mode).
    // Otherwise, keep logs in RAM to prevent disk activity.
    static HWND hViewer = nullptr;
    static std::mutex viewerMtx; // FIX: Protect static state from data races
    
    // Fix: Rate limit Window search to avoid system-wide iteration on every log line
    // Double-checked locking optimization not strictly needed here given the frequency
    std::lock_guard<std::mutex> lock(viewerMtx);

    if (!IsWindow(hViewer)) {
         static DWORD lastCheckTick = 0;
         DWORD currentTick = GetTickCount();
         if (currentTick - lastCheckTick > 2000) {
             hViewer = FindWindowW(L"PManLogViewer", nullptr);
             lastCheckTick = currentTick;
         }
    }
    
    if (hViewer && IsWindowVisible(hViewer)) {
        // [PERF FIX] Rate limit disk flushing to 1 second
        static uint64_t lastFlush = 0;
        uint64_t nowTick = GetTickCount64();
        if (nowTick - lastFlush > 1000) {
            FlushLogger();
            PostMessageW(hViewer, WM_LOG_UPDATED, 0, 0);
            lastFlush = nowTick;
        }
    }
}
