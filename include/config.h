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

#ifndef PMAN_CONFIG_H
#define PMAN_CONFIG_H
#include <filesystem>
#include <vector>
#include <string>
#include <unordered_set>
#include "explorer_booster.h"
#include "nlohmann/json.hpp" // Required for serialization

// [PHASE 2] Secure Storage & Validation
class ConfigValidator {
public:
    static bool Validate(const nlohmann::json& j);
};

class SecureConfigManager {
public:
    static bool LoadSecureConfig();
    static void SaveSecureConfig();
    static std::filesystem::path GetSecureConfigPath();
    
    // [PATCH] IPC Integration: Apply JSON config directly from Service
    static bool ApplyConfig(const nlohmann::json& j);
};

void LoadConfig();

// Shadow Config Accessors (for GUI)
void SetExplorerConfigShadow(const ExplorerConfig& cfg);
ExplorerConfig GetExplorerConfigShadow();
std::unordered_set<std::wstring> GetBackgroundAppsShadow(); // [FIX] Accessor for background apps
void SaveConfig();
bool CreateDefaultConfig(const std::filesystem::path& configPath);

// Tweak Persistence
struct TweakConfig; // Forward declaration
void LoadTweakPreferences(TweakConfig& config);
void SaveTweakPreferences(const TweakConfig& config);
void SaveIconTheme(const std::wstring& theme);

#endif // PMAN_CONFIG_H
