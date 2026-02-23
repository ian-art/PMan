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
 
#include "provenance_ledger.h"
#include "logger.h"
#include "utils.h" // Required for WideToUtf8
#include "context.h" // Required for FaultState
#include <string>
#include <fstream>
#include <iomanip>

static std::string ReasonToString(RejectionReason r) {
    switch(r) {
        case RejectionReason::HigherCost: return "HigherCost";
        case RejectionReason::LowerBenefit: return "LowerBenefit";
        case RejectionReason::PolicyViolation: return "PolicyViolation";
        case RejectionReason::LowConfidence: return "LowConfidence";
        case RejectionReason::UnstableIntent: return "UnstableIntent";
        case RejectionReason::CooldownActive: return "CooldownActive";
        case RejectionReason::BudgetInsufficient: return "BudgetInsufficient";
        case RejectionReason::SandboxRejected: return "SandboxRejected";
        case RejectionReason::ManualOverride: return "ManualOverride";
        case RejectionReason::ExternalDenial: return "ExternalDenial";
        case RejectionReason::TargetAccessDenied: return "TargetAccessDenied";
        case RejectionReason::ApiFailure: return "ApiFailure";
        default: return "Unknown";
    }
}

ProvenanceLedger::ProvenanceLedger() : m_healthy(true) {
    m_ledger.reserve(1024);
}

ProvenanceLedger::~ProvenanceLedger() {
    // In a full implementation, this might flush remaining records to a distinct file.
}

bool ProvenanceLedger::IsProvenanceSecure() const {
    return m_healthy;
}

void ProvenanceLedger::Record(const DecisionJustification& record) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // [FAULT INJECTION]
    if (PManContext::Get().fault.ledgerWriteFail) {
        m_healthy = false;
        Log("[FAULT] ProvenanceLedger: Write Failure Simulated. Ledger marked unhealthy.");
        return; 
    }

    if (!m_healthy) return;

    try {
        // 1. Immutable Append
        m_ledger.push_back(record);

        // 2. Structured Log Stream (JSONL style for auditability)
        // This ensures the forensic trail is visible in the main log immediately.
        std::string json = "{";
        json += "\"tick\": " + std::to_string(record.timestamp) + ", ";
        json += "\"action\": " + std::to_string((int)record.actionType) + ", ";
        json += "\"conf_var\": [" + std::to_string(record.cpuVariance) + "," + 
                                     std::to_string(record.thermalVariance) + "," + 
                                     std::to_string(record.latencyVariance) + "], ";
        json += "\"intent\": " + std::to_string(record.intentStabilityCount) + ", ";
        json += "\"budget_pre\": " + std::to_string(record.authorityBudgetBefore) + ", ";
        json += "\"cost\": " + std::to_string(record.authorityCost) + ", ";
        json += "\"committed\": " + std::string(record.finalCommitted ? "true" : "false") + ", ";
        json += "\"policy_hash\": \"" + record.policyHash + "\"";
        json += "}";

        Log("[PROVENANCE] " + json);

    } catch (...) {
        // Hard Failure: If we cannot record, we must flag the system as insecure.
        m_healthy = false;
        Log("[CRITICAL] Provenance Ledger write failed. Authority Locked.");
    }
}

void ProvenanceLedger::ExportLog(const std::wstring& filePath) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    try {
        std::ofstream file(filePath);
        if (!file.is_open()) {
            Log("[AUDIT] Failed to open file for export: " + WideToUtf8(filePath.c_str()));
            return;
        }

        file << "[\n";
        for (size_t i = 0; i < m_ledger.size(); ++i) {
            const auto& rec = m_ledger[i];
            file << "  {\n";
            file << "    \"tick\": " << rec.timestamp << ",\n";
            file << "    \"action\": " << (int)rec.actionType << ",\n";
            file << "    \"conf_variance\": [" 
                 << rec.cpuVariance << ", " 
                 << rec.thermalVariance << ", " 
                 << rec.latencyVariance << "],\n";
            file << "    \"intent_stable_count\": " << rec.intentStabilityCount << ",\n";
            file << "    \"budget_before\": " << rec.authorityBudgetBefore << ",\n";file << "    \"cost\": " << rec.authorityCost << ",\n";
            file << "    \"sandbox_committed\": " << (rec.finalCommitted ? "true" : "false") << ",\n";
            file << "    \"sandbox_reason\": \"" << (rec.sandboxResult.reason ? rec.sandboxResult.reason : "None") << "\",\n";
            file << "    \"policy_hash\": \"" << rec.policyHash << "\",\n";
            
            file << "    \"external_verdict\": {\n";
            file << "      \"state\": \"" << rec.externalVerdict.state << "\",\n";
            file << "      \"expires_at_tick\": " << rec.externalVerdict.expiresAt << "\n";
            file << "    },\n";

            file << "    \"counterfactuals\": [\n";
            for (size_t j = 0; j < rec.counterfactuals.size(); ++j) {
                const auto& cf = rec.counterfactuals[j];
                file << "      { \"action\": " << (int)cf.action << ", \"reason\": \"" << ReasonToString(cf.reason) << "\" }"
                     << (j < rec.counterfactuals.size() - 1 ? "," : "") << "\n";
            }
            file << "    ]\n";

            file << "  }" << (i < m_ledger.size() - 1 ? "," : "") << "\n";
        }
        file << "]\n";
        
        Log("[AUDIT] Authority Log exported to: " + WideToUtf8(filePath.c_str()));
    } catch (...) {
        Log("[AUDIT] Exception during audit export.");
    }
}
