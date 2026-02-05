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

#ifndef PMAN_POLICY_CONTRACT_H
#define PMAN_POLICY_CONTRACT_H

#include "types.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <memory>

// Mirror of policy.json structure
struct PolicyLimits {
    std::unordered_set<int> allowedActions; // Stored as int to avoid enum dependency issues in parsing
    int maxConcurrentActions = 1;
    int maxAuthorityBudget = 100;
    uint64_t maxLeaseMs = 5000;
    
    struct {
        double cpuVariance = 0.01;
        double latencyVariance = 0.02;
    } minConfidence;
    
    int intentStability = 3;
    bool humanResetRequired = true;
};

class PolicyGuard {
public:
    PolicyGuard();
    ~PolicyGuard();

    // Loads policy.json. Returns false if file missing or invalid.
    bool Load(const std::wstring& path);

    // The Hard Gate: Validates action against the loaded contract
    bool Validate(BrainAction action, double cpuVariance, double latencyVariance);

    // Returns SHA-256 hash of the loaded policy file
    std::string GetHash() const { return m_hash; }

    const PolicyLimits& GetLimits() const { return m_limits; }

private:
    PolicyLimits m_limits;
    std::string m_hash;
    
    std::string ComputeFileHash(const std::wstring& path);
    bool ParsePolicy(const std::string& jsonContent);
};

#endif // PMAN_POLICY_CONTRACT_H
