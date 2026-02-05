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

#ifndef PMAN_EXTERNAL_VERDICT_H
#define PMAN_EXTERNAL_VERDICT_H

#include "types.h"
#include <string>
#include <vector>
#include <unordered_set>

enum class VerdictType {
    ALLOW,
    DENY,
    CONSTRAIN,
    NONE // Missing or Invalid
};

struct VerdictResult {
    bool allowed;
    std::string stateStr; // "ALLOW", "DENY", "CONSTRAIN", "NONE"
    uint64_t expiresAt;
    std::string reason;
};

class ExternalVerdict {
public:
    ExternalVerdict();
    ~ExternalVerdict();

    // Check if the action is permitted by the external verdict file
    VerdictResult Check(BrainAction action);

private:
    struct VerdictData {
        VerdictType type = VerdictType::NONE;
        std::unordered_set<int> allowedActions;
        uint64_t expiresAt = 0;
        bool valid = false;
    };

    VerdictData LoadVerdict(const std::wstring& path);
    VerdictData ParseVerdict(const std::string& json);
};

#endif // PMAN_EXTERNAL_VERDICT_H
