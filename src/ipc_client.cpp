/*
 * This file is part of Priority Manager (PMan).
 * Copyright (c) 2026 Ian Anthony R. Tancinco
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
    // SECURITY: FILE_FLAG_OVERLAPPED is not used here for simplicity in this synchronous call
    UniqueHandle hPipe(CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,              // No sharing
        nullptr,        // Default security attributes
        OPEN_EXISTING,
        0,              // Default attributes
        nullptr
    ));

    if (!hPipe || hPipe.get() == INVALID_HANDLE_VALUE) {
        return { false, "Connection Failed: Could not open secure pipe.", false };
    }

    // 4. Transmission Logic
    DWORD bytesWritten = 0;
    if (!WriteFile(hPipe.get(), payload.c_str(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr)) {
        return { false, "Transmission Error: Failed to send data to service.", false };
    }

    // 5. Read Verdict
    char buffer[4096];
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe.get(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
        return { false, "Protocol Error: Service did not acknowledge request.", false };
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
