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

#ifndef PMAN_IPC_SERVER_H
#define PMAN_IPC_SERVER_H

#include "types.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <chrono>

// Forward declaration for JSON support
#include <nlohmann/json.hpp>

class IpcServer {
public:
    IpcServer();
    ~IpcServer();

    // Starts the IPC Listener Thread
    void Initialize();
    
    // Stops the listener and closes pipes
    void Shutdown();

private:
    void WorkerThread();
    void ProcessRequest(const std::string& request, std::string& response, HANDLE hPipe);
    
    // The "Diamond Patch": Internal Role-Based Access Control
    bool ValidateCaller(HANDLE hPipe, bool& isAdmin, bool& isInteractive);
    bool IsAdmin(HANDLE hToken);
    bool IsInteractive(HANDLE hToken);

    // Rate Limiting (Token Bucket)
    struct RateBucket {
        std::chrono::steady_clock::time_point lastRefill;
        int tokens;
    };
    std::unordered_map<DWORD, RateBucket> m_clientBuckets;
    bool CheckRateLimit(HANDLE hPipe);

    std::atomic<bool> m_running{false};
    std::thread m_worker;
    HANDLE m_hShutdownEvent = nullptr; // [PATCH] Event for clean shutdown
    
    // Hardcoded Pipe Name
    const std::wstring PIPE_NAME = L"\\\\.\\pipe\\PManSecureInterface";
};

#endif // PMAN_IPC_SERVER_H
