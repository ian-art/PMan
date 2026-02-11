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

#include "ipc_server.h"
#include "logger.h"
#include "globals.h"
#include "config.h"           // [PATCH] For SecureConfigManager
#include "context.h"          // [PATCH] For Policy/Faults
#include "policy.h"           // [FIX] Required for PolicyGuard class definition
#include "policy_contract.h"  // [FIX] Required for PolicyLimits struct definition
#include "external_verdict.h" // [PATCH] For Verdict
#include <sddl.h>
#include <aclapi.h>
#include <vector>

using json = nlohmann::json;

IpcServer::IpcServer() = default;

IpcServer::~IpcServer() {
    Shutdown();
}

void IpcServer::Initialize() {
    if (m_running.load()) return;

    m_running.store(true);
    m_worker = std::thread(&IpcServer::WorkerThread, this);
    Log("[IPC] Secure Server Initialized (Pipe: PManSecureInterface)");
}

void IpcServer::Shutdown() {
    if (!m_running.load()) return;
    
    m_running.store(false);
    
    // Connect to self to unblock ConnectNamedPipe if it's waiting
    HANDLE hPipe = CreateFileW(PIPE_NAME.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);

    if (m_worker.joinable()) m_worker.join();
    Log("[IPC] Server Shutdown.");
}

void IpcServer::WorkerThread() {
    // 1. Create Security Descriptor (SYSTEM:Full, Admins:RW, Interactive:RW)
    // D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)", 
            SDDL_REVISION_1, 
            &(sa.lpSecurityDescriptor), 
            nullptr)) {
        Log("[IPC] CRITICAL: Failed to create Security Descriptor. IPC Aborted.");
        return;
    }

    while (m_running.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Log("[IPC] Failed to create pipe instance. Retrying in 1s...");
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            // [PATCH] Fix Pipe Clog DoS: Enforce timeouts
            COMMTIMEOUTS timeouts = { 0 };
            timeouts.ReadIntervalTimeout = 500;
            timeouts.ReadTotalTimeoutConstant = 500;
            timeouts.ReadTotalTimeoutMultiplier = 0;
            SetCommTimeouts(hPipe, &timeouts);

            // Rate Limiter Defense
            // Prevent "Pipe Spam" DoS by dropping high-frequency callers immediately
            if (!CheckRateLimit(hPipe)) {
                Log("[IPC] Rate Limit Exceeded. Dropping connection.");
                FlushFileBuffers(hPipe);
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                continue;
            }

            // Handle Connection
            char buffer[4096];
            DWORD bytesRead;
            std::string requestData;

            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
                buffer[bytesRead] = '\0';
                requestData = buffer;
                
                std::string responseData;
                ProcessRequest(requestData, responseData, hPipe);
                
                DWORD bytesWritten;
                WriteFile(hPipe, responseData.c_str(), (DWORD)responseData.length(), &bytesWritten, nullptr);
            }
        }

        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    LocalFree(sa.lpSecurityDescriptor);
}

// The "Diamond Patch": Internal RBAC
bool IpcServer::ValidateCaller(HANDLE hPipe, bool& isAdmin, bool& isInteractive) {
    if (!ImpersonateNamedPipeClient(hPipe)) return false;

    HANDLE hToken;
    bool result = false;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        isAdmin = IsAdmin(hToken);
        isInteractive = IsInteractive(hToken);
        CloseHandle(hToken);
        result = true;
    }

    RevertToSelf();
    return result;
}

bool IpcServer::IsAdmin(HANDLE hToken) {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = FALSE;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        if (!CheckTokenMembership(hToken, AdministratorsGroup, &b)) b = FALSE;
        FreeSid(AdministratorsGroup);
    }
    return b == TRUE;
}

bool IpcServer::IsInteractive(HANDLE hToken) {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID InteractiveGroup;
    BOOL b = FALSE;
    if (AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &InteractiveGroup)) {
        if (!CheckTokenMembership(hToken, InteractiveGroup, &b)) b = FALSE;
        FreeSid(InteractiveGroup);
    }
    return b == TRUE;
}

bool IpcServer::CheckRateLimit(HANDLE hPipe) {
    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(hPipe, &clientPid)) {
        // If we can't identify the PID, we can't rate limit effectively.
        // Fail open to avoid breaking legitimate obscure cases, but log it?
        // For now, allow it.
        return true; 
    }

    auto now = std::chrono::steady_clock::now();
    
    // Policy: 10 Requests / Second (Burst Size)
    // This allows UI spam (clicking buttons) but stops script spam.
    const int MAX_TOKENS = 10;
    const auto REFILL_INTERVAL = std::chrono::seconds(1);

    auto& bucket = m_clientBuckets[clientPid];
    
    // Lazy Refill
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - bucket.lastRefill);
    if (elapsed >= REFILL_INTERVAL) {
        bucket.tokens = MAX_TOKENS;
        bucket.lastRefill = now;
    }

    if (bucket.tokens > 0) {
        bucket.tokens--;
        return true;
    }

    return false;
}

void IpcServer::ProcessRequest(const std::string& request, std::string& response, HANDLE hPipe) {
    json req;
    json resp;
    
    try {
        req = json::parse(request);
    } catch (...) {
        resp["status"] = "error";
        resp["message"] = "Invalid JSON";
        response = resp.dump();
        return;
    }

    // 1. Authenticate
    bool isAdmin = false;
    bool isInteractive = false;
    if (!ValidateCaller(hPipe, isAdmin, isInteractive)) {
        resp["status"] = "error";
        resp["message"] = "Authentication Failed";
        response = resp.dump();
        Log("[IPC] Auth Failed for request.");
        return;
    }

    std::string cmd = req["cmd"].get<std::string>();

    // 2. Authorize (RBAC)
    // Only Admin can write config or control service state
    // Interactive users can only query status (read-only)
    
    if (cmd == "GET_STATUS") {
        // Safe for Interactive
        resp["status"] = "ok";
        resp["running"] = g_running.load();
        resp["mode"] = (int)g_lastMode.load();
        // Add more status fields here
    }
    else if (cmd == "RELOAD_CONFIG") {
        if (!isAdmin) {
            resp["status"] = "denied";
            resp["message"] = "Requires Administrator";
        } else {
            g_reloadNow.store(true);
            resp["status"] = "ok";
            Log("[IPC] Admin triggered Config Reload.");
        }
    }
    // [PATCH] Handle Configuration Update
    else if (cmd == "SET_CONFIG") {
        if (!isAdmin) {
            resp["status"] = "denied";
            resp["message"] = "Requires Administrator";
        } else {
            // [FIX] Extract payload from envelope
            if (!req.contains("data")) {
                resp["status"] = "error";
                resp["message"] = "Protocol Error: Missing data field";
                response = resp.dump();
                return;
            }
            const auto& payload = req["data"];

            // Check for special subsystems first
            if (payload.contains("policy")) {
                const auto& pol = payload["policy"];
                PolicyLimits limits;
                if (pol.contains("max_authority_budget")) limits.maxAuthorityBudget = pol["max_authority_budget"];
                if (pol.contains("min_confidence")) {
                    limits.minConfidence.cpuVariance = pol["min_confidence"].value("cpu_variance", 0.01);
                    limits.minConfidence.latencyVariance = pol["min_confidence"].value("latency_variance", 0.02);
                }
                if (pol.contains("allowed_actions")) {
                    for (const auto& act : pol["allowed_actions"]) {
                        limits.allowedActions.insert(act.get<int>());
                    }
                }
                
                if (PManContext::Get().subs.policy) {
                    PManContext::Get().subs.policy->Save(GetLogPath() / L"policy.json", limits);
                    g_reloadNow.store(true);
                    resp["status"] = "ok";
                    Log("[IPC] Policy updated via Service.");
                } else {
                    resp["status"] = "error";
                    resp["message"] = "Policy Engine not ready";
                }
            }
            else if (payload.contains("verdict")) {
                 const auto& v = payload["verdict"];
                 std::string status = v.value("status", "ALLOW");
                 int duration = v.value("duration_sec", 3600);
                 
                 VerdictType type = VerdictType::ALLOW;
                 if (status == "DENY") type = VerdictType::DENY;
                 if (status == "CONSTRAIN") type = VerdictType::CONSTRAIN;

                 ExternalVerdict::SaveVerdict(GetLogPath() / L"verdict.json", type, duration);
                 resp["status"] = "ok";
                 Log("[IPC] External Verdict applied: " + status);
            }
            else if (payload.contains("debug") && payload["debug"].contains("faults")) {
                const auto& f = payload["debug"]["faults"];
                auto& ctxFault = PManContext::Get().fault;
                
                ctxFault.ledgerWriteFail = f.value("ledger_write_fail", false);
                ctxFault.budgetCorruption = f.value("budget_corruption", false);
                ctxFault.sandboxError = f.value("sandbox_error", false);
                ctxFault.intentInvalid = f.value("intent_invalid", false);
                ctxFault.confidenceInvalid = f.value("confidence_invalid", false);
                
                resp["status"] = "ok";
                Log("[IPC] Debug Faults injected.");
            }
            else {
                // Standard Configuration (Global, Explorer, Lists)
                if (SecureConfigManager::ApplyConfig(payload)) {
                    resp["status"] = "ok";
                    g_reloadNow.store(true); // Trigger internal re-read if needed
                    Log("[IPC] Configuration updated securely.");
                } else {
                    resp["status"] = "error";
                    resp["message"] = "Validation Failed";
                }
            }
        }
    }
    else {
        resp["status"] = "error";
        resp["message"] = "Unknown Command";
    }

    response = resp.dump();
}
