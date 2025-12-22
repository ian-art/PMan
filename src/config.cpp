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

// Fix 4.3: Input Validation Helper
static bool IsValidExecutableName(const std::string& name)
{
    if (name.empty() || name.length() > 64) return false;
    
    // Must end in .exe
    if (name.length() < 4 || name.substr(name.length() - 4) != ".exe") return false;
    
    // No path separators allowed (filename only)
    if (name.find_first_of("/\\") != std::string::npos) return false;

    // Critical System Processes Blacklist
    static const std::unordered_set<std::string> BLACKLIST = {
        "svchost.exe", "csrss.exe", "wininit.exe", "services.exe", 
        "lsass.exe", "winlogon.exe", "smss.exe", "system", "registry",
        "audiodg.exe", "dwm.exe", "spoolsv.exe"
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
        std::unordered_set<std::string> games, browsers, gameWindows, browserWindows;
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
                std::string secNameAscii = WideToUtf8(secName.c_str());
                asciiLower(secNameAscii);
                
				if (secNameAscii == "global") sect = GLOBAL;
                else if (secNameAscii == "meta") sect = META;
                else if (secNameAscii == "games") sect = G;
                else if (secNameAscii == "browsers") sect = B;
                else if (secNameAscii == "game_windows") sect = GW;
                else if (secNameAscii == "browser_windows") sect = BW;
                else sect = NONE;
                continue;
            }
            
            // Handle Meta Section
            if (sect == META)
            {
                size_t eqPos = item.find('=');
                if (eqPos != std::string::npos)
                {
                    std::string key = item.substr(0, eqPos);
                    std::string value = item.substr(eqPos + 1);
                    // Simple trim/lower
                    asciiLower(key);
                    if (key.find("version") != std::string::npos) {
                        try { configVersion = std::stoi(value); } catch(...) { configVersion = 0; }
                    }
                }
                continue;
            }
            
            std::string item = WideToUtf8(s.c_str());
            
            if (sect == GLOBAL)
            {
                size_t eqPos = item.find('=');
                if (eqPos != std::string::npos)
                {
                    std::string key = item.substr(0, eqPos);
                    std::string value = item.substr(eqPos + 1);
                    
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t") + 1);
                    
                    asciiLower(key);
                    asciiLower(value);
                    
                    if (key == "ignore_non_interactive")
                    {
                        ignoreNonInteractive = (value == "true" || value == "1" || value == "yes");
                    }
                    else if (key == "restore_on_exit")
                    {
                        restoreOnExit = (value == "true" || value == "1" || value == "yes");
                    }
                    else if (key == "suspend_updates_during_games")
                    {
                        g_suspendUpdatesDuringGames.store(value == "true" || value == "1" || value == "yes");
                    }
                    else if (key == "lock_policy")
                    {
                        lockPolicy = (value == "true" || value == "1" || value == "yes");
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
                    Log("[CFG] Skipped unsafe/invalid entry: " + item);
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