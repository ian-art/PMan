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

#include "ipc_client.h"
#include "utils.h" // For UniqueHandle
#include <windows.h>

using json = nlohmann::json;

namespace {
    // Helper: Check if the current process has administrative privileges
    bool IsCurrentProcessElevated() {
        bool fRet = false;
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION Elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
                fRet = Elevation.TokenIsElevated;
            }
        }
        if (hToken) {
            CloseHandle(hToken);
        }
        return fRet;
    }
}

IpcClient::Response IpcClient::SendConfig(const json& configData) {
    // 1. Identity Verification (The "Badge" Check)
    if (!IsCurrentProcessElevated()) {
        return { false, "Access Denied: Administrator rights are required to modify system configuration.", true };
    }

    // 2. The Communication Protocol (JSON Framing)
    json envelope;
    envelope["cmd"] = "SET_CONFIG";
    envelope["data"] = configData;

    std::string payload = envelope.dump();
    const std::wstring pipeName = L"\\\\.\\pipe\\PManSecureInterface";

    // 3. The Connection Layer (Pipe Plumbing)
    // Wait for the service to be available (timeout: 2 seconds)
    if (!WaitNamedPipeW(pipeName.c_str(), 2000)) {
        return { false, "Connection Failed: PMan Service is not running or busy.", false };
    }

    // Connect to the pipe
    // [PATCH] Use OVERLAPPED for robust async I/O
    UniqueHandle hPipe(CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, // Enabled async mode
        nullptr
    ));

    if (!hPipe || hPipe.get() == INVALID_HANDLE_VALUE) {
        return { false, "Connection Failed: Could not open secure pipe.", false };
    }

    // Helper: Async Operation with Timeout
    auto PerformAsync = [&](auto func, void* buffer, DWORD size, DWORD& transferred) -> bool {
        OVERLAPPED ov = {0};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;
        
        UniqueHandle hEvent(ov.hEvent); // RAII cleanup

        if (!func(hPipe.get(), buffer, size, &transferred, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) return false;
            
            // Wait up to 2000ms
            if (WaitForSingleObject(ov.hEvent, 2000) != WAIT_OBJECT_0) {
                CancelIo(hPipe.get()); // Timeout!
                return false;
            }
            return GetOverlappedResult(hPipe.get(), &ov, &transferred, FALSE) != 0;
        }
        return true; // Completed immediately
    };

    // 4. Transmission Logic
    DWORD bytesWritten = 0;
    // Adapt WriteFile signature for helper
    auto WriteOp = [](HANDLE h, void* b, DWORD s, DWORD* t, LPOVERLAPPED o) {
        return WriteFile(h, b, s, t, o);
    };
    
    // Cast away constness safely for the API
    if (!PerformAsync(WriteOp, (void*)payload.c_str(), (DWORD)payload.size(), bytesWritten)) {
        return { false, "Transmission Error: Send timeout or failure.", false };
    }

    // 5. Read Verdict
    char buffer[4096];
    DWORD bytesRead = 0;
    auto ReadOp = ReadFile; // Direct signature match

    if (!PerformAsync(ReadOp, buffer, sizeof(buffer) - 1, bytesRead)) {
        return { false, "Protocol Error: Receive timeout.", false };
    }

    buffer[bytesRead] = '\0'; // Null-terminate

    try {
        auto response = json::parse(buffer);
        std::string status = response.value("status", "error");
        
        if (status == "ok") {
            return { true, "Configuration saved successfully.", false };
        } else if (status == "denied") {
            return { false, "Access Denied by Service Policy.", true };
        } else {
            return { false, "Service Error: " + response.value("message", "Unknown error"), false };
        }
    } catch (...) {
        return { false, "Protocol Error: Invalid JSON response from service.", false };
    }
}
