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

#include "config.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "static_tweaks.h"
#include "network_monitor.h" // For SetBackgroundApps
#include "context.h"
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm> // Required for std::transform
#include <cctype>    // Required for ::tolower
#include <windows.h>
#include <wincrypt.h>
#include "nlohmann/json.hpp" // JSON Support
#pragma comment(lib, "Crypt32.lib") // DPAPI Linkage
#include <sstream>

// Helper
static std::filesystem::path GetConfigPath()
{
    return GetLogPath() / CONFIG_FILENAME;
}

// Forward declaration to fix compiler error C3861
static bool IsValidExecutableName(const std::wstring& name);

static std::unordered_set<std::wstring> GetDefaultCustomLaunchers() {
    return {
        L"steam.exe", L"epicgameslauncher.exe", L"battle.net.exe"
    };
}

static std::unordered_set<std::wstring> GetDefaultBrowsers() {
    return {
        L"chrome.exe", L"firefox.exe", L"msedge.exe", L"brave.exe", L"opera.exe",
        L"vivaldi.exe", L"discord.exe", L"spotify.exe", L"slack.exe", L"teams.exe"
    };
}

// Internal shadow copies for serialization (Moved up for SecureConfigManager)
static ExplorerConfig g_lastExplorerConfig;
static std::unordered_set<std::wstring> g_shadowBackgroundApps;
static TweakConfig g_tweakConfig; // [PATCH] In-memory storage for tweaks

static std::unordered_set<std::wstring> GetDefaultIgnoredProcesses() {
    return {
        L"searchhost.exe", L"startmenuexperiencehost.exe",
        L"shellexperiencehost.exe", L"applicationframehost.exe",
        L"lockapp.exe", L"textinputhost.exe", L"ctfmon.exe", L"smartscreen.exe",
        L"taskmgr.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"conhost.exe",
        L"explorer.exe", L"werfault.exe", L"dllhost.exe", L"systemsettings.exe", L"sihost.exe"
    };
}

// Input Validation Helper
static bool IsValidExecutableName(const std::wstring& name)
{
    if (name.empty() || name.length() > 64) return false;
    
    // Must end in .exe
    if (name.length() < 4 || name.substr(name.length() - 4) != L".exe") return false;
    
    // No path separators allowed (filename only)
    if (name.find_first_of(L"/\\") != std::wstring::npos) return false;

    // Validation: Ensure strict filename (rejects ".." and relative paths)
    if (std::filesystem::path(name).filename().wstring() != name) return false;

    // Check for reserved device names
    std::wstring stem = name.substr(0, name.length() - 4);
    static const std::unordered_set<std::wstring> RESERVED_NAMES = {
        L"con", L"prn", L"aux", L"nul", 
        L"com1", L"com2", L"com3", L"com4", L"com5", L"com6", L"com7", L"com8", L"com9",
        L"lpt1", L"lpt2", L"lpt3", L"lpt4", L"lpt5", L"lpt6", L"lpt7", L"lpt8", L"lpt9"
    };
    if (RESERVED_NAMES.count(stem)) return false;

    // Critical System Processes Blacklist
    static const std::unordered_set<std::wstring> BLACKLIST = {
        L"svchost.exe", L"csrss.exe", L"wininit.exe", L"services.exe", 
        L"lsass.exe", L"winlogon.exe", L"smss.exe", L"system", L"registry",
        L"audiodg.exe", L"dwm.exe", L"spoolsv.exe"
    };
    
    if (BLACKLIST.count(name)) return false;
    
    return true;
}

// Integrity & Lifecycle Protection
#pragma pack(push, 1)
struct ConfigHeader {
    uint32_t magic;      // 0x4E414D50 'PMAN' (Little Endian)
    uint64_t version;    // Monotonic Version Counter
    uint8_t hmac[32];    // SHA-256 Signature
    uint32_t blobSize;
};
#pragma pack(pop)

// Registry: The Authority on "Time" (Version)
static uint64_t GetRegistryConfigVersion() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\PMan", 0, NULL, 0, KEY_READ, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        uint64_t ver = 0;
        DWORD size = sizeof(ver);
        if (RegQueryValueExW(hKey, L"ConfigVersion", NULL, NULL, (LPBYTE)&ver, &size) != ERROR_SUCCESS) ver = 0;
        RegCloseKey(hKey);
        return ver;
    }
    return 0;
}

static void SetRegistryConfigVersion(uint64_t ver) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\PMan", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"ConfigVersion", 0, REG_QWORD, (const BYTE*)&ver, sizeof(ver));
        RegCloseKey(hKey);
    }
}

// HMAC: Binds Version + Machine + Data
static void ComputeIntegrityHash(const void* blob, size_t size, uint64_t version, uint8_t* outHash) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            uint32_t magic = 0x4E414D50;
            CryptHashData(hHash, (BYTE*)&magic, sizeof(magic), 0);
            CryptHashData(hHash, (BYTE*)&version, sizeof(version), 0);
            
            // Machine Binding (Prevents cross-device config spoofing)
            wchar_t compName[MAX_PATH] = {0};
            DWORD nameLen = MAX_PATH;
            GetComputerNameW(compName, &nameLen);
            CryptHashData(hHash, (BYTE*)compName, nameLen * sizeof(wchar_t), 0);
            
            // Data Binding
            CryptHashData(hHash, (BYTE*)blob, (DWORD)size, 0);
            
            DWORD hashLen = 32;
            CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

// Configuration Validator
using json = nlohmann::json;

bool ConfigValidator::Validate(const json& j) {
    // 1. Blacklist Protection (Prevent throttling critical system processes)
    static const std::unordered_set<std::string> CRITICAL_BLACKLIST = {
        "explorer.exe", "csrss.exe", "pman.exe", "svchost.exe", 
        "lsass.exe", "wininit.exe", "services.exe", "winlogon.exe"
    };

    auto CheckList = [&](const std::string& listName) {
        if (j.contains(listName)) {
            for (const auto& item : j[listName]) {
                std::string s = item.get<std::string>();
                // Fix C4244: Explicitly cast to char to silence warning about int->char conversion
                std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)::tolower(c); }); 

                if (!IsValidExecutableName(Utf8ToWide(s.c_str()))) {
                    Log("[VALIDATOR] Security Violation: Invalid path or characters in '" + s + "'");
                    return false;
                }

                if (CRITICAL_BLACKLIST.count(s)) {
                    Log("[VALIDATOR] Security Violation: Attempt to target critical process '" + s + "' in " + listName);
                    return false;
                }
            }
        }
        return true;
    };

    if (!CheckList("games")) return false;
    if (!CheckList("background_apps")) return false;
    if (!CheckList("browsers")) return false;

    // 2. Sanity Checks
	if (j.contains("global") && j["global"].contains("idle_timeout")) {
     uint32_t val = 300000;
     const auto& t = j["global"]["idle_timeout"];
     
     try {
         if (t.is_number()) {
             val = t.get<uint32_t>();
         } else if (t.is_string()) {
             std::string s = t.get<std::string>();
             if (s.length() > 1) {
                 uint32_t mul = 1000;
                 if (s.back() == 'm') mul = 60000;
                 // Robust parsing: "300s" -> 300
                 size_t len = s.length();
                 if (!isdigit((unsigned char)s.back())) len--;
                 val = std::stoi(s.substr(0, len)) * mul;
             }
         }
     } catch (...) {}

     if (val < 5000) {
         Log("[VALIDATOR] Sanity Check Failed: idle_timeout too low.");
         return false;
     }
}

    return true;
}

std::filesystem::path SecureConfigManager::GetSecureConfigPath() {
    return GetLogPath() / "config.dat";
}

// Helper to decrypt and validate a specific file
static bool InternalLoadFile(const std::filesystem::path& path, json& outJson) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    ConfigHeader header = {0};
    std::vector<BYTE> cipherText;
    
    // Peek at header
    if (f.read((char*)&header, sizeof(header)) && header.magic == 0x4E414D50) {

        uint64_t sysVersion = GetRegistryConfigVersion();
        
        // Hardcoded Security Floor
        static const uint64_t MIN_SECURE_VERSION = 15;
        if (header.version < MIN_SECURE_VERSION) {
            Log("[SECURE_CFG] CRITICAL: Config version " + std::to_string(header.version) + 
                " is below security floor " + std::to_string(MIN_SECURE_VERSION) + ". Rejected.");
            return false;
        }

        // 1. Anti-Rollback Check
        if (header.version < sysVersion) {
            Log("[SECURE_CFG] Rollback prevention: File v" + std::to_string(header.version) + 
                " < Registry v" + std::to_string(sysVersion));
            return false;
        }

        // 2. Read Payload
        cipherText.resize(header.blobSize);
        f.read((char*)cipherText.data(), header.blobSize);
        
        // 3. Integrity Check (HMAC)
        uint8_t calcHash[32] = {0};
        ComputeIntegrityHash(cipherText.data(), cipherText.size(), header.version, calcHash);
        if (memcmp(calcHash, header.hmac, 32) != 0) {
            Log("[SECURE_CFG] Integrity Violation (HMAC Mismatch). File rejected.");
            return false;
        }

        // 4. Update High Water Mark (if file is newer than registry)
        if (header.version > sysVersion) {
            SetRegistryConfigVersion(header.version);
        }
    } else {
        // --- LEGACY FALLBACK ---
        f.seekg(0, std::ios::beg);
        cipherText.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }
    f.close();

    if (cipherText.empty()) return false;

    DATA_BLOB in, out;
    in.pbData = cipherText.data();
    in.cbData = (DWORD)cipherText.size();

    // Decrypt (System/User bound via DPAPI)
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return false;
    }

    std::string plainText((char*)out.pbData, out.cbData);
    LocalFree(out.pbData);

    try {
        outJson = json::parse(plainText);
        return ConfigValidator::Validate(outJson);
    } catch (...) {
        return false;
    }
}

// [PATCH] IPC Integration
bool SecureConfigManager::ApplyConfig(const json& j) {
    // 2. Apply to Globals (Thread-Safe)
	try {
    // 1. Validate Input (Reject malicious paths/names) - Moved inside try-catch for safety
    if (!ConfigValidator::Validate(j)) {
        Log("[SECURE_CFG] ApplyConfig rejected by validator.");
        return false;
    }

    std::unique_lock lg(g_setMtx);
        
        // Helper to update sets only if present in JSON
        auto UpdateSet = [&](const char* key, std::unordered_set<std::wstring>& target) {
            if (j.contains(key)) {
                target.clear();
                for (const auto& item : j[key]) target.insert(Utf8ToWide(item.get<std::string>().c_str()));
            }
        };

        UpdateSet("games", g_games);
        UpdateSet("browsers", g_browsers);
        UpdateSet("video_players", g_videoPlayers);
        UpdateSet("background_apps", g_shadowBackgroundApps);
        UpdateSet("old_games", g_oldGames);
        UpdateSet("game_windows", g_gameWindows);
        UpdateSet("browser_windows", g_browserWindows);
        UpdateSet("custom_launchers", g_customLaunchers);
        UpdateSet("ignored_processes", g_ignoredProcesses);
        
        if (j.contains("global")) {
            auto& g = j["global"];
            if (g.contains("ignore_non_interactive")) g_ignoreNonInteractive.store(g["ignore_non_interactive"]);
            if (g.contains("restore_on_exit")) g_restoreOnExit.store(g["restore_on_exit"]);
            if (g.contains("lock_policy")) g_lockPolicy.store(g["lock_policy"]);
            if (g.contains("suspend_updates_during_games")) g_suspendUpdatesDuringGames.store(g["suspend_updates_during_games"]);
            if (g.contains("idle_revert_enabled")) g_idleRevertEnabled.store(g["idle_revert_enabled"]);
            
            if (g.contains("idle_timeout")) {
             uint32_t ms = 300000;
             const auto& t = g["idle_timeout"];
             
             if (t.is_number()) {
                 ms = t.get<uint32_t>();
             } else if (t.is_string()) {
                 std::string s = t.get<std::string>();
                 if (s.length() > 1) {
                     uint32_t mul = 1000;
                     if (s.back() == 'm') mul = 60000;
                     size_t len = s.length();
                     if (!isdigit((unsigned char)s.back())) len--;
                     try { ms = std::stoi(s.substr(0, len)) * mul; } catch(...) {}
                 }
             }
             g_idleTimeoutMs.store(ms);
        }

            if (g.contains("responsiveness_recovery")) g_responsivenessRecoveryEnabled.store(g["responsiveness_recovery"]);
            if (g.contains("recovery_prompt")) g_recoveryPromptEnabled.store(g["recovery_prompt"]);
            if (g.contains("enable_brain")) PManContext::Get().conf.enableBrain.store(g["enable_brain"]);
            if (g.contains("icon_theme")) g_iconTheme = Utf8ToWide(g["icon_theme"].get<std::string>().c_str());
        }

        if (j.contains("explorer")) {
            auto& e = j["explorer"];
            ExplorerConfig cfg = g_lastExplorerConfig; // Start with current
            
            if (e.contains("enabled")) cfg.enabled = e["enabled"];
            if (e.contains("boost_dwm")) cfg.boostDwm = e["boost_dwm"];
            if (e.contains("boost_io_priority")) cfg.boostIoPriority = e["boost_io_priority"];
            if (e.contains("disable_power_throttling")) cfg.disablePowerThrottling = e["disable_power_throttling"];
            if (e.contains("prevent_shell_paging")) cfg.preventShellPaging = e["prevent_shell_paging"];
            if (e.contains("debug_logging")) cfg.debugLogging = e["debug_logging"];

            if (e.contains("idle_threshold")) {
                 std::string s = e["idle_threshold"];
                 uint32_t ms = 15000;
                 if (!s.empty()) {
                     uint32_t mul = 1000;
                     if (s.back() == 'm') mul = 60000;
                     try { ms = std::stoi(s.substr(0, s.size()-1)) * mul; } catch(...) {}
                 }
                 cfg.idleThresholdMs = ms;
            }
             if (e.contains("scan_interval")) {
                 std::string s = e["scan_interval"];
                 uint32_t ms = 5000;
                 if (!s.empty()) {
                     uint32_t mul = 1000;
                     if (s.back() == 'm') mul = 60000;
                     try { ms = std::stoi(s.substr(0, s.size()-1)) * mul; } catch(...) {}
                 }
                 cfg.scanIntervalMs = ms;
            }

            g_lastExplorerConfig = cfg;
            if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->UpdateConfig(cfg);
        }

        // [PATCH] Apply Tweaks
        if (j.contains("tweaks")) {
            auto& t = j["tweaks"];
            g_tweakConfig.network = t.value("network", false);
            g_tweakConfig.services = t.value("services", false);
            g_tweakConfig.privacy = t.value("privacy", false);
            g_tweakConfig.explorer = t.value("explorer", false);
            g_tweakConfig.power = t.value("power", false);
            g_tweakConfig.location = t.value("location", false);
            g_tweakConfig.dvr = t.value("dvr", false);
            g_tweakConfig.bloatware = t.value("bloatware", false);
        }
        
    // Sync Subsystems
    g_networkMonitor.SetBackgroundApps(g_shadowBackgroundApps);
    
    lg.unlock(); // [PATCH] Explicitly unlock before saving to prevent deadlock

	} catch (const std::exception& e) {
    Log("[SECURE_CFG] JSON Apply Error: " + std::string(e.what()));
    return false;
	}

	// 3. Persist to Disk (Using the secure saver)
	SaveSecureConfig();
	return true;
}

bool SecureConfigManager::LoadSecureConfig() {
    json j;
    bool loaded = InternalLoadFile(GetSecureConfigPath(), j);

    if (!loaded) {
        // Backup Recovery Strategy
        // If main config is corrupt (BSOD/Power Loss during save), try the .bak
        std::filesystem::path backupPath = GetSecureConfigPath();
        backupPath += ".bak";
        
        if (std::filesystem::exists(backupPath)) {
            Log("[SECURE_CFG] WARNING: Main configuration corrupt. Attempting backup recovery...");
            if (InternalLoadFile(backupPath, j)) {
                Log("[SECURE_CFG] CRISIS AVERTED: Successfully restored configuration from backup.");
                loaded = true;
                
                // Self-Heal: Restore the backup to the main slot immediately
                try {
                    std::filesystem::copy_file(backupPath, GetSecureConfigPath(), std::filesystem::copy_options::overwrite_existing);
                } catch(...) {}
            }
        }
    }

    if (!loaded) return false;

    // Apply to Globals (Deserialization)
    try {
        {
            std::unique_lock lg(g_setMtx);
            
            auto LoadSet = [&](const char* key, std::unordered_set<std::wstring>& target) {
                target.clear();
                if (j.contains(key)) {
                    for (const auto& item : j[key]) target.insert(Utf8ToWide(item.get<std::string>().c_str()));
                }
            };

            LoadSet("games", g_games);
            LoadSet("browsers", g_browsers);
            LoadSet("video_players", g_videoPlayers);
            LoadSet("background_apps", g_shadowBackgroundApps);
            LoadSet("old_games", g_oldGames);
            LoadSet("game_windows", g_gameWindows);
            LoadSet("browser_windows", g_browserWindows);
            LoadSet("custom_launchers", g_customLaunchers);
            LoadSet("ignored_processes", g_ignoredProcesses);
            
            if (j.contains("global")) {
                auto& g = j["global"];
                g_ignoreNonInteractive.store(g.value("ignore_non_interactive", true));
                g_restoreOnExit.store(g.value("restore_on_exit", true));
                g_lockPolicy.store(g.value("lock_policy", false));
                g_suspendUpdatesDuringGames.store(g.value("suspend_updates", false));
                g_idleRevertEnabled.store(g.value("idle_revert", true));
                g_idleTimeoutMs.store(g.value("idle_timeout", 300000));
                g_responsivenessRecoveryEnabled.store(g.value("responsiveness_recovery", true));
                g_recoveryPromptEnabled.store(g.value("recovery_prompt", true));
                PManContext::Get().conf.enableBrain.store(g.value("enable_brain", true));
                g_iconTheme = Utf8ToWide(g.value("icon_theme", "Default").c_str());
            }

            if (j.contains("explorer")) {
                auto& e = j["explorer"];
                ExplorerConfig cfg;
                cfg.enabled = e.value("enabled", false);
                cfg.idleThresholdMs = e.value("idle_threshold", 15000);
                cfg.boostDwm = e.value("boost_dwm", true);
                cfg.boostIoPriority = e.value("boost_io", false);
                cfg.disablePowerThrottling = e.value("disable_throttling", true);
                cfg.preventShellPaging = e.value("prevent_paging", true);
                cfg.scanIntervalMs = e.value("scan_interval", 5000);
                g_lastExplorerConfig = cfg;
                if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->UpdateConfig(cfg);
            }

            if (j.contains("tweaks")) {
                auto& t = j["tweaks"];
                g_tweakConfig.network = t.value("network", false);
                g_tweakConfig.services = t.value("services", false);
                g_tweakConfig.privacy = t.value("privacy", false);
                g_tweakConfig.explorer = t.value("explorer", false);
                g_tweakConfig.power = t.value("power", false);
                g_tweakConfig.location = t.value("location", false);
                g_tweakConfig.dvr = t.value("dvr", false);
                g_tweakConfig.bloatware = t.value("bloatware", false);
            }
            
            // Sync Subsystems
            g_networkMonitor.SetBackgroundApps(g_shadowBackgroundApps);
        }
        
        Log("[SECURE_CFG] Configuration loaded successfully.");
        return true;

    } catch (const std::exception& e) {
        Log("[SECURE_CFG] JSON Parse Error during apply: " + std::string(e.what()));
        return false;
    }
}

void SecureConfigManager::SaveSecureConfig() {
    try {
        json j;
        
        {
            std::shared_lock lg(g_setMtx);
            
            auto SaveSet = [&](const char* key, const std::unordered_set<std::wstring>& source) {
                for (const auto& item : source) j[key].push_back(WideToUtf8(item.c_str()));
            };

            SaveSet("games", g_games);
            SaveSet("browsers", g_browsers);
            SaveSet("video_players", g_videoPlayers);
            SaveSet("background_apps", g_shadowBackgroundApps);
            SaveSet("old_games", g_oldGames);
            SaveSet("game_windows", g_gameWindows);
            SaveSet("browser_windows", g_browserWindows);
            SaveSet("custom_launchers", g_customLaunchers);
            SaveSet("ignored_processes", g_ignoredProcesses);

            j["global"] = {
                {"ignore_non_interactive", g_ignoreNonInteractive.load()},
                {"restore_on_exit", g_restoreOnExit.load()},
                {"lock_policy", g_lockPolicy.load()},
                {"suspend_updates", g_suspendUpdatesDuringGames.load()},
                {"idle_revert", g_idleRevertEnabled.load()},
                {"idle_timeout", g_idleTimeoutMs.load()},
                {"responsiveness_recovery", g_responsivenessRecoveryEnabled.load()},
                {"recovery_prompt", g_recoveryPromptEnabled.load()},
                {"enable_brain", PManContext::Get().conf.enableBrain.load()},
                {"icon_theme", WideToUtf8(g_iconTheme.c_str())}
            };
            
            ExplorerConfig ec = g_lastExplorerConfig;
            j["explorer"] = {
                {"enabled", ec.enabled},
                {"idle_threshold", ec.idleThresholdMs},
                {"boost_dwm", ec.boostDwm},
                {"boost_io", ec.boostIoPriority},
                {"disable_throttling", ec.disablePowerThrottling},
                {"prevent_paging", ec.preventShellPaging},
                {"scan_interval", ec.scanIntervalMs}
            };

            j["tweaks"] = {
                {"network", g_tweakConfig.network},
                {"services", g_tweakConfig.services},
                {"privacy", g_tweakConfig.privacy},
                {"explorer", g_tweakConfig.explorer},
                {"power", g_tweakConfig.power},
                {"location", g_tweakConfig.location},
                {"dvr", g_tweakConfig.dvr},
                {"bloatware", g_tweakConfig.bloatware}
            };
        }

        std::string plainText = j.dump();
        
        DATA_BLOB in, out;
        in.pbData = (BYTE*)plainText.data();
        in.cbData = (DWORD)plainText.size();

        if (!CryptProtectData(&in, L"PManConfig", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
            Log("[SECURE_CFG] Encryption Failed.");
            return;
        }

        // Time Lock (Version + Integrity)
        uint64_t nextVer = GetRegistryConfigVersion() + 1;
        if (nextVer < 15) nextVer = 15; // Enforce MIN_SECURE_VERSION for new installations
        SetRegistryConfigVersion(nextVer);
        
        ConfigHeader header;
        header.magic = 0x4E414D50;
        header.version = nextVer;
        header.blobSize = out.cbData;
        
        // Sign the package
        ComputeIntegrityHash(out.pbData, out.cbData, header.version, header.hmac);

        // Atomic Save Strategy
        // 1. Write to .tmp file
        std::filesystem::path finalPath = GetSecureConfigPath();
        std::filesystem::path tempPath = finalPath; tempPath += ".tmp";
        std::filesystem::path backupPath = finalPath; backupPath += ".bak";

        {
            std::ofstream f(tempPath, std::ios::binary | std::ios::trunc);
            if (!f) throw std::runtime_error("Could not create temp config");
            f.write((char*)&header, sizeof(header));
            f.write((char*)out.pbData, out.cbData);
            if (f.bad()) throw std::runtime_error("Write failed");
            f.close(); 
        } // Ensure handle is closed before move
        
        LocalFree(out.pbData);

        // 2. Rotate: Current -> Backup
        // We use MoveFileEx with REPLACE_EXISTING. If finalPath doesn't exist (first run), it fails gracefully.
        MoveFileExW(finalPath.c_str(), backupPath.c_str(), MOVEFILE_REPLACE_EXISTING);

        // 3. Promote: Temp -> Current
        if (MoveFileExW(tempPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            Log("[SECURE_CFG] Atomic save complete v" + std::to_string(nextVer));
        } else {
            Log("[SECURE_CFG] CRITICAL: Failed to promote temp config!");
        }

    } catch (...) {
        Log("[SECURE_CFG] Save failed.");
    }
}

static std::unordered_set<std::wstring> GetDefaultBackgroundApps() {
    return {
        L"onedrive.exe", L"googledrivesync.exe", L"dropbox.exe", L"box.exe",
        L"steam.exe", L"epicgameslauncher.exe", L"battle.net.exe", L"eadesktop.exe", L"upc.exe",
        L"qbittorrent.exe", L"u torrent.exe", L"transmission-qt.exe", L"idman.exe"
    };
}

bool CreateDefaultConfig(const std::filesystem::path& configPath)
{
    // [FIX] Silence "unreferenced parameter" warning (C4100)
    (void)configPath; 

    // [SECURITY] Create Secure Defaults directly in memory. Do NOT write INI.
    try {
        std::unique_lock lg(g_setMtx);
        
        // 1. Populate Defaults
        g_browsers = GetDefaultBrowsers();
        g_shadowBackgroundApps = GetDefaultBackgroundApps();
        g_customLaunchers = GetDefaultCustomLaunchers();
        g_ignoredProcesses = GetDefaultIgnoredProcesses();
        
        g_games.clear(); g_videoPlayers.clear(); g_oldGames.clear();
        g_gameWindows.clear(); g_browserWindows.clear();
        
        g_ignoreNonInteractive.store(true);
        g_restoreOnExit.store(true);
        g_lockPolicy.store(false);
        g_suspendUpdatesDuringGames.store(false);
        g_idleRevertEnabled.store(false);
        g_idleTimeoutMs.store(300000);
        g_responsivenessRecoveryEnabled.store(true);
        g_recoveryPromptEnabled.store(true);
        PManContext::Get().conf.enableBrain.store(true);
        g_iconTheme = L"Default";
        
        ExplorerConfig ec = {};
        ec.enabled = false;
        ec.idleThresholdMs = 15000;
        ec.boostDwm = true;
        ec.disablePowerThrottling = true;
        ec.preventShellPaging = true;
        ec.scanIntervalMs = 5000;
        g_lastExplorerConfig = ec;
        if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->UpdateConfig(ec);
        
        g_tweakConfig = {}; // Reset tweaks
    } catch (...) {}

    // 2. Save immediately as Encrypted .dat
    SecureConfigManager::SaveSecureConfig();
    Log("[CONFIG] Initialized secure defaults.");
    return true;
}

void LoadConfig()
{
    // [SECURITY] Only load from Secure Storage.
    // If loading fails (missing/corrupt), strictly initialize defaults.
    // Never fallback to INI parsing.
    if (!SecureConfigManager::LoadSecureConfig()) {
        Log("[CONFIG] Secure config missing or invalid. Creating new secure container.");
        CreateDefaultConfig(GetConfigPath());
    }
}

void SaveConfig()
{
    // Secure Save
    SecureConfigManager::SaveSecureConfig();
}

void LoadTweakPreferences(TweakConfig& config)
{
    // [SECURITY] Load from memory cache (populated by SecureConfigManager)
    config = g_tweakConfig;
}

void SaveTweakPreferences(const TweakConfig& config)
{
    // [SECURITY] Update memory and sync to Secure Storage
    g_tweakConfig = config;
    SecureConfigManager::SaveSecureConfig();
}

void SaveIconTheme(const std::wstring& theme)
{
    {
        std::unique_lock lg(g_setMtx);
        g_iconTheme = theme;
    }
    // [SECURITY] Sync to Secure Storage
    SecureConfigManager::SaveSecureConfig();
}

void SetExplorerConfigShadow(const ExplorerConfig& cfg) {
    std::unique_lock lg(g_setMtx);
    g_lastExplorerConfig = cfg;
}

ExplorerConfig GetExplorerConfigShadow() {
    std::shared_lock lg(g_setMtx);
    return g_lastExplorerConfig;
}

std::unordered_set<std::wstring> GetBackgroundAppsShadow() {
    std::shared_lock lg(g_setMtx);
    return g_shadowBackgroundApps;
}
