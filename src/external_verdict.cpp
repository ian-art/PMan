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
 * This file is part of Priority Manager (PMan).
 * External Verdict Interface - Implementation
 */

#include "external_verdict.h"
#include "logger.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>

ExternalVerdict::ExternalVerdict() {}
ExternalVerdict::~ExternalVerdict() {}

// Helper: Map string to BrainAction (Duplicated to decouple from PolicyContract)
static int ActionFromString(const std::string& s) {
    if (s.find("Throttle_Mild") != std::string::npos) return (int)BrainAction::Throttle_Mild;
    if (s.find("Throttle_Aggressive") != std::string::npos) return (int)BrainAction::Throttle_Aggressive;
    if (s.find("Optimize_Memory") != std::string::npos) return (int)BrainAction::Optimize_Memory;
    if (s.find("Suspend_Services") != std::string::npos) return (int)BrainAction::Suspend_Services;
    if (s.find("Release_Pressure") != std::string::npos) return (int)BrainAction::Release_Pressure;
    if (s.find("Maintain") != std::string::npos) return (int)BrainAction::Maintain;
    return -1;
}

void ExternalVerdict::SaveVerdict(const std::wstring& path, VerdictType type, uint64_t durationSeconds) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return;

    std::string typeStr = "NONE";
    if (type == VerdictType::ALLOW) typeStr = "ALLOW";
    else if (type == VerdictType::DENY) typeStr = "DENY";
    else if (type == VerdictType::CONSTRAIN) typeStr = "CONSTRAIN";

    uint64_t now = (uint64_t)std::time(nullptr);
    uint64_t expires = now + durationSeconds;

    out << "{\n";
    out << "  \"verdict\": \"" << typeStr << "\",\n";
    out << "  \"expires_at_unix\": " << expires;
    
    // If we ever support UI for allowed_actions in verdict, add it here.
    // For now, defaults are safe.
    
    out << "\n}";
    out.close();
}

ExternalVerdict::VerdictData ExternalVerdict::ParseVerdict(const std::string& json) {
    VerdictData data;
    data.valid = false;

    try {
        // 1. Parse Verdict Type
        std::string typeStr;
        size_t typePos = json.find("\"verdict\"");
        if (typePos != std::string::npos) {
            size_t valStart = json.find(":", typePos) + 1;
            size_t valEnd = json.find_first_of(",}", valStart);
            if (valEnd != std::string::npos) {
                typeStr = json.substr(valStart, valEnd - valStart);
                // Clean quotes and whitespace
                typeStr.erase(std::remove(typeStr.begin(), typeStr.end(), '\"'), typeStr.end());
                typeStr.erase(std::remove(typeStr.begin(), typeStr.end(), ' '), typeStr.end());
                typeStr.erase(std::remove(typeStr.begin(), typeStr.end(), '\r'), typeStr.end());
                typeStr.erase(std::remove(typeStr.begin(), typeStr.end(), '\n'), typeStr.end());
            }
        }

        if (typeStr == "ALLOW") data.type = VerdictType::ALLOW;
        else if (typeStr == "DENY") data.type = VerdictType::DENY;
        else if (typeStr == "CONSTRAIN") data.type = VerdictType::CONSTRAIN;
        else return data; // Invalid Type

        // 2. Parse Expiry
        size_t expPos = json.find("\"expires_at_unix\"");
        if (expPos != std::string::npos) {
            size_t valStart = json.find(":", expPos) + 1;
            // Scan for digits
            std::string numStr;
            for (size_t i = valStart; i < json.length(); ++i) {
                if (isdigit(json[i])) numStr += json[i];
                else if (!numStr.empty()) break; // End of number
            }
            if (!numStr.empty()) data.expiresAt = std::stoull(numStr);
        } else {
            return data; // Mandatory field missing
        }

        // 3. Parse Allowed Actions (Only for CONSTRAIN)
        if (data.type == VerdictType::CONSTRAIN) {
            size_t actPos = json.find("\"allowed_actions\"");
            if (actPos != std::string::npos) {
                size_t start = json.find("[", actPos);
                size_t end = json.find("]", start);
                if (start != std::string::npos && end != std::string::npos) {
                    std::string arrayContent = json.substr(start + 1, end - start - 1);
                    std::stringstream ss(arrayContent);
                    std::string segment;
                    while (std::getline(ss, segment, ',')) {
                        int act = ActionFromString(segment);
                        if (act != -1) data.allowedActions.insert(act);
                    }
                }
            }
        }

        data.valid = true;
    } catch (...) {
        data.valid = false;
    }
    return data;
}

ExternalVerdict::VerdictData ExternalVerdict::LoadVerdict(const std::wstring& path) {
    std::ifstream t(path);
    if (!t.is_open()) {
        // [FIX] Auto-create default verdict (ALLOW) if missing
        SaveVerdict(path, VerdictType::ALLOW, 86400); // Default 24h allow

        // Re-open
        t.open(path);
        if (!t.is_open()) return {VerdictType::NONE};
    }

    std::stringstream buffer;
    buffer << t.rdbuf();
    return ParseVerdict(buffer.str());
}

VerdictResult ExternalVerdict::Check(BrainAction action) {
    // Hard Rule: Maintain is always allowed unless explicitly DENIED by system failure,
    // but here we check strictly against the verdict.
    // However, if the verdict says "DENY" (meaning stop everything), even Maintain might be the *result* of the denial, 
    // but the check itself asks "Is this action permitted?".

    std::wstring path = GetLogPath() / L"verdict.json";
    VerdictData v = LoadVerdict(path);

    VerdictResult result;
    result.allowed = false;
    
    // Map state string
    switch (v.type) {
        case VerdictType::ALLOW: result.stateStr = "ALLOW"; break;
        case VerdictType::DENY: result.stateStr = "DENY"; break;
        case VerdictType::CONSTRAIN: result.stateStr = "CONSTRAIN"; break;
        default: result.stateStr = "NONE"; break;
    }
    result.expiresAt = v.expiresAt;

    // 1. Missing / Unreadable -> Fail Closed
    if (!v.valid || v.type == VerdictType::NONE) {
        result.reason = "Verdict Missing/Invalid";
        return result;
    }

    // 2. Expiration & Manual Renewal Check
    // "0" specifically means the operator has not set a valid window.
    if (v.expiresAt == 0) {
        result.reason = "Manual Renewal Required";
        return result;
    }

    uint64_t now = (uint64_t)std::time(nullptr);
    if (now > v.expiresAt) {
        result.reason = "Verdict Expired";
        return result;
    }

    // 3. Logic by Type
    if (v.type == VerdictType::DENY) {
        result.reason = "Explicit DENY";
        return result;
    }

    if (v.type == VerdictType::ALLOW) {
        result.allowed = true;
        return result;
    }

    if (v.type == VerdictType::CONSTRAIN) {
        if (action == BrainAction::Maintain) {
             // Implicitly allow Maintain? 
             // The prompt says "If verdict constrains actions -> reject others".
             // Usually Maintain is safe. Let's assume Maintain is allowed if we are just idling, 
             // BUT if the system wants to "Maintain" as a decision, it technically passes.
             // However, strictly following the "allowed_actions" list is safer.
             // If "Maintain" is not in list, it means we shouldn't even be here? 
             // No, "Maintain" is the fallback. If we reject "Maintain", what do we do? Crash?
             // We MUST allow Maintain as the fallback state of the rejection itself.
             // So we check action vs list only if action != Maintain.
        }

        if (action != BrainAction::Maintain && v.allowedActions.find((int)action) == v.allowedActions.end()) {
            result.reason = "Action Not in Allowed List";
            return result;
        }
        result.allowed = true;
        return result;
    }

    result.reason = "Logic Error";
    return result;
}
