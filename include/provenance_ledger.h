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

#ifndef PMAN_PROVENANCE_LEDGER_H
#define PMAN_PROVENANCE_LEDGER_H

#include "types.h"
#include "sandbox_executor.h" // For SandboxResult
#include <vector>
#include <mutex>

// Immutable Snapshot of Decision Context
// "Why exactly did the system believe it was justified?"
struct DecisionJustification {
    BrainAction actionType;
    uint64_t timestamp;

    // Confidence Variance Snapshot
    double cpuVariance;
    double thermalVariance;
    double latencyVariance;

    // Intent & Budget Context
    uint32_t intentStabilityCount;
    int authorityBudgetBefore;
    int authorityCost;

    // Execution Outcomes
    SandboxResult sandboxResult;
    bool rollbackGuardTriggered; // Should be false if executed
    bool finalCommitted;
};

class ProvenanceLedger {
public:
    ProvenanceLedger();
    ~ProvenanceLedger();

    // Verification Gate: Must return true before authority is spent
    bool IsProvenanceSecure() const;

    // Append-Only Write
    void Record(const DecisionJustification& justification);

    // Read-Only Audit Export (Snapshot to File)
    void ExportLog(const std::wstring& filePath) const;

private:
    std::vector<DecisionJustification> m_ledger;
    mutable std::mutex m_mutex; // Mutable to allow locking in const methods
    bool m_healthy;
};

#endif // PMAN_PROVENANCE_LEDGER_H
