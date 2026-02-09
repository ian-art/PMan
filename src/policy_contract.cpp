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

#include "policy_contract.h"
#include "logger.h"
#include "utils.h"
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "Advapi32.lib") // For CryptoAPI

PolicyGuard::PolicyGuard() {}
PolicyGuard::~PolicyGuard() {}

// Helper: Simple string mapping for BrainAction (Update matches types.h)
static int ActionFromString(const std::string& s) {
    if (s.find("Throttle_Mild") != std::string::npos) return (int)BrainAction::Throttle_Mild;
    if (s.find("Throttle_Aggressive") != std::string::npos) return (int)BrainAction::Throttle_Aggressive;
    if (s.find("Throttle_Strong") != std::string::npos) return (int)BrainAction::Throttle_Aggressive; // Alias
    if (s.find("Optimize_Memory_Gentle") != std::string::npos) return (int)BrainAction::Optimize_Memory_Gentle;
    if (s.find("Optimize_Memory") != std::string::npos) return (int)BrainAction::Optimize_Memory;
    if (s.find("Suspend_Services") != std::string::npos) return (int)BrainAction::Suspend_Services;
    if (s.find("Release_Pressure") != std::string::npos) return (int)BrainAction::Release_Pressure;
    if (s.find("Boost_Process") != std::string::npos) return (int)BrainAction::Boost_Process; // [FIX] No longer aliased
    if (s.find("Shield_Foreground") != std::string::npos) return (int)BrainAction::Shield_Foreground;
    if (s.find("Maintain") != std::string::npos) return (int)BrainAction::Maintain;
    return -1;
}

std::string PolicyGuard::ComputeFileHash(const std::wstring& path) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE rgbFile[1024];
    DWORD cbRead = 0;
    BYTE rgbHash[32]; // SHA-256 is 32 bytes
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    std::string hexHash = "";

    hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "HASH_FAIL_FILE_ACCESS";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile); return "HASH_FAIL_CTX";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CloseHandle(hFile); CryptReleaseContext(hProv, 0); return "HASH_FAIL_CREATE";
    }

    while (ReadFile(hFile, rgbFile, 1024, &cbRead, NULL)) {
        if (cbRead == 0) break;
        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            CloseHandle(hFile); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return "HASH_FAIL_DATA";
        }
    }

    cbHash = 32;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (DWORD i = 0; i < cbHash; i++) {
            hexHash += rgbDigits[rgbHash[i] >> 4];
            hexHash += rgbDigits[rgbHash[i] & 0xf];
        }
    } else {
        hexHash = "HASH_FAIL_PARAM";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return hexHash;
}

static std::string ActionToString(int action) {
    switch ((BrainAction)action) {
        case BrainAction::Throttle_Mild: return "Throttle_Mild";
        case BrainAction::Throttle_Aggressive: return "Throttle_Aggressive";
        case BrainAction::Optimize_Memory_Gentle: return "Optimize_Memory_Gentle";
        case BrainAction::Optimize_Memory: return "Optimize_Memory";
        case BrainAction::Suspend_Services: return "Suspend_Services";
        case BrainAction::Release_Pressure: return "Release_Pressure";
        case BrainAction::Shield_Foreground: return "Shield_Foreground";
        case BrainAction::Boost_Process: return "Boost_Process"; // [FIX] Added case
        case BrainAction::Maintain: return "Maintain";
        default: return "Maintain";
    }
}

std::string PolicyGuard::SerializePolicy(const PolicyLimits& limits) {
    std::stringstream ss;
    ss << "{\n";
    // 1. Budget & Thresholds first (User Preference)
    ss << "  \"max_authority_budget\": " << limits.maxAuthorityBudget << ",\n";
    ss << "  \"min_confidence_threshold\": {\n";
    ss << "    \"cpu_variance\": " << limits.minConfidence.cpuVariance << ",\n";
    ss << "    \"thermal_variance\": " << limits.minConfidence.thermalVariance << ",\n";
    ss << "    \"latency_variance\": " << limits.minConfidence.latencyVariance << "\n";
    ss << "  },\n";
    
    // 2. Allowed Actions last
    ss << "  \"allowed_actions\": [\n";
    bool first = true;
    for (int act : limits.allowedActions) {
        if (!first) ss << ",\n";
        ss << "    \"" << ActionToString(act) << "\"";
        first = false;
    }
    ss << "\n  ]\n";
    ss << "}";
    return ss.str();
}

bool PolicyGuard::Save(const std::wstring& path, const PolicyLimits& limits) {
    try {
        std::ofstream out(path, std::ios::trunc);
        if (!out.is_open()) return false;
        out << SerializePolicy(limits);
        out.close();
        
        // Update local hash immediately to prevent tampering detection on next load
        m_hash = ComputeFileHash(path); 
        return true;
    } catch (...) {
        return false;
    }
}

// Minimalistic JSON Parser for Policy Schema
bool PolicyGuard::ParsePolicy(const std::string& json) {
    try {
        // Defaults
        m_limits = PolicyLimits();

        // 1. Allowed Actions
        size_t actionPos = json.find("\"allowed_actions\"");
        if (actionPos != std::string::npos) {
            size_t start = json.find("[", actionPos);
            size_t end = json.find("]", start);
            if (start != std::string::npos && end != std::string::npos) {
                std::string arrayContent = json.substr(start + 1, end - start - 1);
                std::stringstream ss(arrayContent);
                std::string segment;
                while (std::getline(ss, segment, ',')) {
                    int act = ActionFromString(segment);
                    if (act != -1) m_limits.allowedActions.insert(act);
                }
            }
        }

        // 2. Budget
        size_t budPos = json.find("\"max_authority_budget\"");
        if (budPos != std::string::npos) {
            size_t valStart = json.find(":", budPos) + 1;
            m_limits.maxAuthorityBudget = std::stoi(json.substr(valStart));
        }

        // 3. Confidence Thresholds
        size_t confPos = json.find("\"min_confidence_threshold\"");
        if (confPos != std::string::npos) {
            size_t cpuPos = json.find("\"cpu_variance\"", confPos);
            if (cpuPos != std::string::npos) {
                size_t valStart = json.find(":", cpuPos) + 1;
                m_limits.minConfidence.cpuVariance = std::stod(json.substr(valStart));
            }
            size_t thermPos = json.find("\"thermal_variance\"", confPos);
            if (thermPos != std::string::npos) {
                size_t valStart = json.find(":", thermPos) + 1;
                m_limits.minConfidence.thermalVariance = std::stod(json.substr(valStart));
            }
            size_t latPos = json.find("\"latency_variance\"", confPos);
            if (latPos != std::string::npos) {
                size_t valStart = json.find(":", latPos) + 1;
                m_limits.minConfidence.latencyVariance = std::stod(json.substr(valStart));
            }
        }
        
        return true;
    } catch (...) {
        Log("[POLICY] JSON Parsing failed. Using strict defaults.");
        return false;
    }
}

bool PolicyGuard::Load(const std::wstring& path) {
    // 1. Auto-Create Default if Missing
    if (!std::filesystem::exists(path)) {
        Log("[POLICY] Policy file missing. Creating default safety contract.");
        PolicyLimits defaults;
        defaults.allowedActions = {
            (int)BrainAction::Maintain,
            (int)BrainAction::Throttle_Mild,
            (int)BrainAction::Optimize_Memory,
            (int)BrainAction::Release_Pressure,
            (int)BrainAction::Boost_Process
        };
        Save(path, defaults);
    }

    // 2. Compute Hash (Pinning)
    m_hash = ComputeFileHash(path);
    if (m_hash.find("HASH_FAIL") != std::string::npos) {
        Log("[POLICY] Failed to compute hash. Policy load aborted.");
        return false;
    }

    // 3. Load Content
    std::ifstream t(path);
    if (!t.is_open()) return false;
    
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string content = buffer.str();

    // 3. Parse
    if (ParsePolicy(content)) {
        std::string logMsg = "[POLICY] Contract Loaded: Budget=" + std::to_string(m_limits.maxAuthorityBudget) +
                             " | Var_CPU=" + std::to_string(m_limits.minConfidence.cpuVariance) +
                             " | Var_Lat=" + std::to_string(m_limits.minConfidence.latencyVariance) +
                             " | Actions=" + std::to_string(m_limits.allowedActions.size());
        Log(logMsg);
        return true;
    }
    return false;
}

bool PolicyGuard::Validate(BrainAction action, double cpuVariance, double latencyVariance) {
    // Rule 1: Allowed Action Check
    // Always allow Maintain
    if (action != BrainAction::Maintain) {
        if (m_limits.allowedActions.find((int)action) == m_limits.allowedActions.end()) {
            return false;
        }
    }

    // Rule 2: Confidence Threshold (Lower variance is better)
    // If current variance is HIGHER than allowed threshold, we reject.
    if (cpuVariance > m_limits.minConfidence.cpuVariance) return false;
    if (latencyVariance > m_limits.minConfidence.latencyVariance) return false;

    return true;
}
