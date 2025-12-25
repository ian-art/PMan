#include "config.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include <fstream>
#include <iostream>
#include <string>

// Helper
static std::filesystem::path GetConfigPath()
{
    return GetLogPath() / CONFIG_FILENAME;
}

// Fix Input Validation Helper
static bool IsValidExecutableName(const std::wstring& name)
{
    if (name.empty() || name.length() > 64) return false;
    
    // Must end in .exe
    if (name.length() < 4 || name.substr(name.length() - 4) != L".exe") return false;
    
	// No path separators allowed (filename only)
    if (name.find_first_of(L"/\\") != std::wstring::npos) return false;

    // Validation: Ensure strict filename (rejects ".." and relative paths)
    if (std::filesystem::path(name).filename().wstring() != name) return false;

    // Check for reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    // Name is already lowercased and confirmed to end in .exe by previous checks
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

bool CreateDefaultConfig(const std::filesystem::path& configPath)
{
    try
    {
        std::filesystem::create_directories(configPath.parent_path());
        
        std::ofstream f(configPath);
        if (!f)
        {
            Log("Failed to create default config at: " + WideToUtf8(configPath.c_str()));
            return false;
        }
        
        f << DEFAULT_CONFIG;
        f.close();
        
        Log("Created default config at: " + WideToUtf8(configPath.c_str()));
        return true;
    }
    catch (const std::exception& e)
    {
        Log(std::string("Exception creating default config: ") + e.what());
        return false;
    }
}

void LoadConfig()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    auto last = g_lastConfigReload.load();
    
    // Debounce check
    static constexpr int CONFIG_RELOAD_DEBOUNCE_MS = 2000; 
    if (last != 0)
    {
        auto elapsed_ms = (now - last) / 1000000;
        if (elapsed_ms < CONFIG_RELOAD_DEBOUNCE_MS)
        {
            return;
        }
    }
    
    g_lastConfigReload.store(now);
    
try
    {
        std::filesystem::path configPath = GetConfigPath();
        std::unordered_set<std::wstring> games, browsers, gameWindows, browserWindows;
        bool ignoreNonInteractive = true;
        bool restoreOnExit = true;
        bool lockPolicy = false;
        
        if (!std::filesystem::exists(configPath))
        {
            Log("Config not found, creating default config...");
            CreateDefaultConfig(configPath);
        }
        
        std::wifstream f(configPath);
        if (!f) 
        { 
            Log("Config not found at: " + WideToUtf8(configPath.c_str())); 
            return; 
        }
        
		std::wstring line;
        enum Sect { NONE, META, GLOBAL, G, B, GW, BW } sect = NONE;
        int lineNum = 0;
        int configVersion = 0; // Default to 0 (legacy/unknown)
        
        while (std::getline(f, line))
        {
            ++lineNum;
            if (lineNum == 1 && !line.empty() && line[0] == 0xFEFF)
                line.erase(0, 1);
            
            size_t first = line.find_first_not_of(L" \t\r\n");
            if (first == std::wstring::npos) continue;
            size_t lastPos = line.find_last_not_of(L" \t\r\n");
            std::wstring s = line.substr(first, lastPos - first + 1);
            
            if (s.empty() || s[0] == L';' || s[0] == L'#') continue;
            
            if (s.front() == L'[' && s.back() == L']')
            {
                std::wstring secName = s.substr(1, s.size() - 2);
                asciiLower(secName);
                
				if (secName == L"global") sect = GLOBAL;
                else if (secName == L"meta") sect = META;
                else if (secName == L"games") sect = G;
                else if (secName == L"browsers") sect = B;
                else if (secName == L"game_windows") sect = GW;
                else if (secName == L"browser_windows") sect = BW;
				else sect = NONE;
                continue;
            }
            
            // Define item here so it's available for all sections
            std::wstring item = s;

            // Handle Meta Section
            if (sect == META)
            {
                size_t eqPos = item.find(L'=');
                if (eqPos != std::wstring::npos)
                {
                    std::wstring key = item.substr(0, eqPos);
                    std::wstring value = item.substr(eqPos + 1);
                    // Simple trim/lower
                    asciiLower(key);
                    if (key.find(L"version") != std::wstring::npos) {
                        try { configVersion = std::stoi(value); } catch(...) { configVersion = 0; }
                    }
				}
                continue;
            }

            if (sect == GLOBAL)
            {
                size_t eqPos = item.find(L'=');
                if (eqPos != std::wstring::npos)
                {
                    std::wstring key = item.substr(0, eqPos);
                    std::wstring value = item.substr(eqPos + 1);
                    
                    key.erase(0, key.find_first_not_of(L" \t"));
                    key.erase(key.find_last_not_of(L" \t") + 1);
                    value.erase(0, value.find_first_not_of(L" \t"));
                    value.erase(value.find_last_not_of(L" \t") + 1);
                    
                    asciiLower(key);
                    asciiLower(value);
                    
                    if (key == L"ignore_non_interactive")
                    {
                        ignoreNonInteractive = (value == L"true" || value == L"1" || value == L"yes");
                    }
                    else if (key == L"restore_on_exit")
                    {
                        restoreOnExit = (value == L"true" || value == L"1" || value == L"yes");
                    }
                    else if (key == L"suspend_updates_during_games")
                    {
                        g_suspendUpdatesDuringGames.store(value == L"true" || value == L"1" || value == L"yes");
                    }
					else if (key == L"lock_policy")
                    {
                        lockPolicy = (value == L"true" || value == L"1" || value == L"yes");
                    }
                    else if (key == L"idle_revert_enabled")
                    {
                        g_idleRevertEnabled.store(value == L"true" || value == L"1" || value == L"yes");
                    }
                    else if (key == L"idle_timeout_minutes")
                    {
                        try { g_idleTimeoutMinutes.store(std::stoi(value)); } catch (...) { g_idleTimeoutMinutes.store(5); }
                    }
                }
                continue;
            }
            
			asciiLower(item);
            
            // Validate inputs before insertion
            if (!IsValidExecutableName(item) && (sect == G || sect == B))
            {
                // Only log if it's not a comment or empty (already filtered above, but safety first)
                if (!item.empty())
                    Log("[CFG] Skipped unsafe/invalid entry: " + WideToUtf8(item.c_str()));
                continue;
            }

            if (sect == G && !item.empty()) games.insert(item);
            if (sect == B && !item.empty()) browsers.insert(item);
            if (sect == GW && !item.empty()) gameWindows.insert(item);
            if (sect == BW && !item.empty()) browserWindows.insert(item);
        }
        
        {
            std::unique_lock lg(g_setMtx);
            g_games = std::move(games);
            g_browsers = std::move(browsers);
            g_gameWindows = std::move(gameWindows);
            g_browserWindows = std::move(browserWindows);
        }
        
        g_ignoreNonInteractive.store(ignoreNonInteractive);
        g_restoreOnExit.store(restoreOnExit);
        g_lockPolicy.store(lockPolicy);
        
        Log("Config loaded: " + std::to_string(g_games.size()) + " games, " +
            std::to_string(g_browsers.size()) + " browsers, " +
            std::to_string(g_gameWindows.size()) + " game windows, " +
            std::to_string(g_browserWindows.size()) + " browser windows | " +
			"ignore_non_interactive=" + (ignoreNonInteractive ? "true" : "false") + " | " +
            "restore_on_exit=" + (restoreOnExit ? "true" : "false") + " | " +
            "lock_policy=" + (lockPolicy ? "true" : "false") + " | " +
            "idle_revert=" + (g_idleRevertEnabled.load() ? "true" : "false") + 
            "(" + std::to_string(g_idleTimeoutMinutes.load()) + "m) | " +
            "suspend_updates=" + (g_suspendUpdatesDuringGames.load() ? "true" : "false"));

        // Fix Migration/Reset Logic
        if (configVersion < CONFIG_VERSION)
        {
            f.close(); // Close reader before moving
            Log("[CONFIG] Version mismatch (File: " + std::to_string(configVersion) + 
                ", App: " + std::to_string(CONFIG_VERSION) + "). backing up and resetting...");
            
            std::filesystem::path backupPath = configPath;
            backupPath += L".old";
            std::filesystem::copy_file(configPath, backupPath, std::filesystem::copy_options::overwrite_existing);
            std::filesystem::remove(configPath);
            CreateDefaultConfig(configPath);
            
            // Recursively load the new config
            LoadConfig(); 
            return;
        }
    }
    catch (const std::exception& e)
    { 
        Log(std::string("LoadConfig exception: ") + e.what()); 
    }
}