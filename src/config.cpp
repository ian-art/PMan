#include "config.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>

// Helper
static std::filesystem::path GetConfigPath()
{
    return GetLogPath() / CONFIG_FILENAME;
}

// Forward declaration to fix compiler error C3861
static bool IsValidExecutableName(const std::wstring& name);

static bool ParseBool(const std::wstring& v) {
    return (v == L"true" || v == L"1" || v == L"yes");
}

static constexpr const char* DEFAULT_IGNORE_LIST = R"(; Priority Manager - Shell Process Exclusion List (ignore_processes.txt)
; These system processes are part of the Desktop Experience.
; They should NEVER be treated as Browsers or Games.
; Add one process per line (lowercase).
mintty.exe
searchhost.exe
startmenuexperiencehost.exe
shellexperiencehost.exe
applicationframehost.exe
systemsettings.exe
lockapp.exe
textinputhost.exe
ctfmon.exe
smartscreen.exe
taskmgr.exe
cmd.exe
powershell.exe
pwsh.exe
conhost.exe
explorer.exe
werfault.exe
dllhost.exe
sihost.exe
)";

// Generic Loader (Fixes Duplication #3)
static void LoadProcessList(const std::filesystem::path& path, 
                            const std::string& defaultContent,
                            std::unordered_set<std::wstring>& outSet)
{
    if (!std::filesystem::exists(path))
    {
        std::ofstream f(path);
        if (f) {
            f << defaultContent;
            f.close();
        }
    }

    std::wifstream f(path);
    if (!f) return;

    std::wstring line;
    while (std::getline(f, line))
    {
        size_t first = line.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos) continue;
        size_t last = line.find_last_not_of(L" \t\r\n");
        std::wstring exe = line.substr(first, last - first + 1);

        if (exe.empty() || exe[0] == L';' || exe[0] == L'#') continue;

        asciiLower(exe);
        if (IsValidExecutableName(exe)) {
            outSet.insert(exe);
        }
    }
}

static void LoadCustomLaunchers(std::unordered_set<std::wstring>& outSet)
{
    std::string defaults = 
        "; Custom Launchers Configuration\n"
        "; List game launchers here to prevent them from being mistaken for games.\n"
        "; These apps will be set to Low Priority to save CPU/GPU for your actual game.\n"
        ";\n"
        "; Add one .exe name per line (lowercase).\n"
        "steam.exe\n"
        "epicGameslauncher.exe\n"
        "battle.net.exe\n";

    LoadProcessList(GetLogPath() / CUSTOM_LAUNCHERS_FILENAME, defaults, outSet);
}

static void LoadIgnoredProcesses(std::unordered_set<std::wstring>& outSet)
{
    LoadProcessList(GetLogPath() / IGNORED_PROCESSES_FILENAME, DEFAULT_IGNORE_LIST, outSet);
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

// Helper function to build config section strings
static std::string BuildConfigSection(const std::string& header, const std::string& content)
{
    std::ostringstream oss;
    oss << "[" << header << "]\n" << content << "\n";
    return oss.str();
}

// Helper function to build key-value pair with comment
static std::string BuildConfigOption(const std::string& comment, const std::string& key, const std::string& value)
{
    std::ostringstream oss;
    if (!comment.empty()) {
        oss << "; " << comment << "\n";
    }
    oss << key << " = " << value << "\n\n";
    return oss.str();
}

// Helper to write configuration data to file (refactored for AV compatibility)
static void WriteConfigurationFile(const std::filesystem::path& path, 
                                   const std::unordered_set<std::wstring>& games,
                                   const std::unordered_set<std::wstring>& browsers,
                                   const std::unordered_set<std::wstring>& oldGames, // New parameter
                                   const std::unordered_set<std::wstring>& gameWindows,
                                   const std::unordered_set<std::wstring>& browserWindows,
                                   bool ignoreNonInteractive,
                                   bool restoreOnExit,
                                   bool lockPolicy,
                                   bool suspendUpdates,
                                   bool idleRevert,
                                   uint32_t idleTimeoutMs,
                                   const ExplorerConfig& explorerConfig)
{
    std::ostringstream buffer;
    
    // Build header
    buffer << "; Priority Manager Configuration\n";
    buffer << "; Configuration file (auto-generated)\n\n";
    
    // Build metadata section
    std::string metaContent = "version=" + std::to_string(CONFIG_VERSION) + "\n";
    buffer << BuildConfigSection("meta", metaContent);
    
    // Build global settings section
    std::ostringstream globalContent;
    
    // Option 1: Background service filtering
    globalContent << BuildConfigOption(
        "Ignore non-interactive processes (services, scheduled tasks, SYSTEM processes)",
        "ignore_non_interactive",
        ignoreNonInteractive ? "true" : "false"
    );
    
    // Option 2: Value restoration
    std::string restoreComment = "Restore original Win32PrioritySeparation value when program exits";
    globalContent << BuildConfigOption(restoreComment, "restore_on_exit", restoreOnExit ? "true" : "false");
    
    // Option 3: Policy protection
    std::string policyKey = "lock_";
    policyKey += "policy";
    globalContent << BuildConfigOption(
        "Prevent external interference from other tweaking tools",
        policyKey,
        lockPolicy ? "true" : "false"
    );
    
    // Option 4: Update handling during gaming sessions
    std::string updateKey = "suspend_updates_";
    updateKey += "during_games";
    globalContent << BuildConfigOption(
        "Pause Windows Update and background transfers during gaming",
        updateKey,
        suspendUpdates ? "true" : "false"
    );
    
    // Option 5: Idle timeout settings
    std::string timeoutStr;
    if (idleTimeoutMs % 60000 == 0) {
        timeoutStr = std::to_string(idleTimeoutMs / 60000);
        timeoutStr += "m";
    } else {
        timeoutStr = std::to_string(idleTimeoutMs / 1000);
        timeoutStr += "s";
    }
    
    globalContent << "; Automatically revert to Browser Mode if system is idle for specified time\n";
    globalContent << "; and no game is currently running.\n";
	globalContent << "idle_revert_enabled = " << (idleRevert ? "true" : "false") << "\n";
    globalContent << "idle_timeout = " << timeoutStr << "\n\n";
    
    buffer << BuildConfigSection("global", globalContent.str());

    // Build Explorer section
    std::ostringstream expContent;
    expContent << "; Smart Shell Boost: Optimizes Windows UI only when system is truly idle\n";
    expContent << "; WARNING: Admin rights required for DWM boosting. Set 'enabled=false' for esports.\n\n";
    
    expContent << "enabled = " << (explorerConfig.enabled ? "true" : "false") << "\n\n";
    
    std::string explorerTimeoutStr;
    if (explorerConfig.idleThresholdMs % 60000 == 0) explorerTimeoutStr = std::to_string(explorerConfig.idleThresholdMs / 60000) + "m";
    else explorerTimeoutStr = std::to_string(explorerConfig.idleThresholdMs / 1000) + "s";

    expContent << "; Idle detection: Time with NO user input AND no foreground game\n";
    expContent << "idle_threshold = " << explorerTimeoutStr << "\n\n";

    expContent << "; Also boost Desktop Window Manager (dwm.exe) for smoother animations\n";
    expContent << "boost_dwm = " << (explorerConfig.boostDwm ? "true" : "false") << "\n\n";

    expContent << "; Apply High I/O priority to file operations (snappier folder loading)\n";
    expContent << "boost_io_priority = " << (explorerConfig.boostIoPriority ? "true" : "false") << "\n\n";

    expContent << "; Disable \"Power Throttling\" (EcoQoS) for Explorer/DWM\n";
    expContent << "disable_power_throttling = " << (explorerConfig.disablePowerThrottling ? "true" : "false") << "\n\n";

    expContent << "; Prevents Windows from paging out Explorer/DWM during gaming\n";
    expContent << "prevent_shell_paging = " << (explorerConfig.preventShellPaging ? "true" : "false") << "\n\n";

    expContent << "; Process scan interval (seconds)\n";
    std::string scanStr = (explorerConfig.scanIntervalMs % 1000 == 0) ? 
                          (std::to_string(explorerConfig.scanIntervalMs / 1000) + "s") : 
                          (std::to_string(explorerConfig.scanIntervalMs) + "ms");
    expContent << "scan_interval = " << scanStr << "\n\n";
    
    expContent << "debug_logging = " << (explorerConfig.debugLogging ? "true" : "false") << "\n\n";

    buffer << BuildConfigSection("explorer", expContent.str());
    
    // Build process lists
    std::ostringstream gamesSection;
    for (const auto& s : games) {
        gamesSection << WideToUtf8(s.c_str()) << "\n";
    }
    buffer << BuildConfigSection("games", gamesSection.str());
    
	std::ostringstream browsersSection;
    for (const auto& s : browsers) {
        browsersSection << WideToUtf8(s.c_str()) << "\n";
    }
    buffer << BuildConfigSection("browsers", browsersSection.str());

    std::ostringstream oldGamesSection;
    for (const auto& s : oldGames) {
        oldGamesSection << WideToUtf8(s.c_str()) << "\n";
    }
    buffer << BuildConfigSection("old_games", oldGamesSection.str());
    
    std::ostringstream gameWindowsSection;
    for (const auto& s : gameWindows) {
        gameWindowsSection << WideToUtf8(s.c_str()) << "\n";
    }
    buffer << BuildConfigSection("game_windows", gameWindowsSection.str());
    
    std::ostringstream browserWindowsSection;
    for (const auto& s : browserWindows) {
        browserWindowsSection << WideToUtf8(s.c_str()) << "\n";
    }
    buffer << BuildConfigSection("browser_windows", browserWindowsSection.str());
    
    // Write buffered content to file in one operation
    std::ofstream outFile(path, std::ios::out | std::ios::trunc);
    if (outFile) {
        outFile << buffer.str();
        outFile.close();
    }
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
    // Reduced to 200ms to allow "correction" updates if the first file-change event read stale data
    // (Common with editors that use temp files or UAC elevation like Notepad++)
    static constexpr int CONFIG_RELOAD_DEBOUNCE_MS = 200; 
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
        std::unordered_set<std::wstring> games, browsers, oldGames, gameWindows, browserWindows, customLaunchers, ignoredProcesses;
        bool ignoreNonInteractive = true;
        bool restoreOnExit = true;

        // Load custom launchers
		LoadIgnoredProcesses(ignoredProcesses);
        LoadCustomLaunchers(customLaunchers);
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
        
        // Explorer config
		ExplorerConfig explorerConfig;
        
        std::wstring line;
        enum Sect { NONE, META, GLOBAL, EXPLORER, G, B, OLD_G, GW, BW } sect = NONE;
        int lineNum = 0;
        int configVersion = 0;
        
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
				else if (secName == L"explorer") sect = EXPLORER;
				else if (secName == L"meta") sect = META;
                else if (secName == L"games") sect = G;
                else if (secName == L"browsers") sect = B;
                else if (secName == L"old_games") sect = OLD_G;
                else if (secName == L"game_windows") sect = GW;
                else if (secName == L"browser_windows") sect = BW;
                else sect = NONE;
                continue;
            }
            
            std::wstring item = s;

            if (sect == META)
            {
                size_t eqPos = item.find(L'=');
                if (eqPos != std::wstring::npos)
                {
                    std::wstring key = item.substr(0, eqPos);
                    std::wstring value = item.substr(eqPos + 1);
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
                    
					if (key == L"ignore_non_interactive") ignoreNonInteractive = ParseBool(value);
                    else if (key == L"restore_on_exit") restoreOnExit = ParseBool(value);
                    else if (key == L"suspend_updates_during_games") g_suspendUpdatesDuringGames.store(ParseBool(value));
                    else if (key == L"lock_policy") lockPolicy = ParseBool(value);
                    else if (key == L"idle_revert_enabled") g_idleRevertEnabled.store(ParseBool(value));
                    else if (key == L"idle_timeout")
                    {
                        if (!value.empty())
                        {
                            wchar_t suffix = value.back();
                            uint32_t multiplier = 60000;
                            std::wstring numPart = value;

                            if (suffix == L's' || suffix == L'S') {
                                multiplier = 1000;
                                numPart.pop_back();
                            }
                            else if (suffix == L'm' || suffix == L'M') {
                                multiplier = 60000;
                                numPart.pop_back();
                            }

                            try {
                                g_idleTimeoutMs.store(static_cast<uint32_t>(std::stoi(numPart)) * multiplier);
                            } catch (...) {
                                g_idleTimeoutMs.store(300000);
                            }
                        }
                    }
				}
                continue;
            }

            if (sect == EXPLORER)
            {
                size_t eqPos = item.find(L'=');
                if (eqPos != std::wstring::npos)
                {
                    std::wstring key = item.substr(0, eqPos);
                    std::wstring value = item.substr(eqPos + 1);
                    
                    // Trim
                    key.erase(0, key.find_first_not_of(L" \t"));
                    key.erase(key.find_last_not_of(L" \t") + 1);
                    value.erase(0, value.find_first_not_of(L" \t"));
                    value.erase(value.find_last_not_of(L" \t") + 1);
                    
                    asciiLower(key);
                    asciiLower(value);
                    
                    auto ParseTime = [](const std::wstring& v) -> uint32_t {
                        if (v.empty()) return 15000;
                        wchar_t suffix = v.back();
                        uint32_t mul = 1000;
                        std::wstring n = v;
                        if (suffix == L's' || suffix == L'S') { n.pop_back(); mul = 1000; }
                        else if (suffix == L'm' || suffix == L'M') { n.pop_back(); mul = 60000; }
                        try { return static_cast<uint32_t>(std::stoi(n)) * mul; } catch(...) { return 15000; }
                    };

					// ParseBool is now static global
                    if (key == L"enabled") explorerConfig.enabled = ParseBool(value);
                    else if (key == L"idle_threshold") explorerConfig.idleThresholdMs = ParseTime(value);
                    else if (key == L"boost_dwm") explorerConfig.boostDwm = ParseBool(value);
                    else if (key == L"boost_io_priority") explorerConfig.boostIoPriority = ParseBool(value);
                    else if (key == L"disable_power_throttling") explorerConfig.disablePowerThrottling = ParseBool(value);
					else if (key == L"prevent_shell_paging") explorerConfig.preventShellPaging = ParseBool(value);
                    else if (key == L"scan_interval") explorerConfig.scanIntervalMs = ParseTime(value);
					else if (key == L"debug_logging") {
						bool parsedValue = ParseBool(value);
						explorerConfig.debugLogging = parsedValue;
    
						// ALWAYS log this to verify it's being parsed correctly
						Log("[CONFIG] Setting debug_logging to: " + WideToUtf8(value.c_str()) + 
						" (parsed as: " + std::string(parsedValue ? "TRUE" : "FALSE") + ")");
					}
                }
                continue;
            }
            
			asciiLower(item);
            
            if (!IsValidExecutableName(item) && (sect == G || sect == B || sect == OLD_G))
            {
                if (!item.empty())
                    Log("[CFG] Skipped unsafe/invalid entry: " + WideToUtf8(item.c_str()));
                continue;
            }

            if (sect == G && !item.empty()) games.insert(item);
            if (sect == B && !item.empty()) browsers.insert(item);
            if (sect == OLD_G && !item.empty()) oldGames.insert(item);
            if (sect == GW && !item.empty()) gameWindows.insert(item);
            if (sect == BW && !item.empty()) browserWindows.insert(item);
        }
        
        // Configuration upgrade handling (preserves user data while updating format)
        bool needsUpgrade = (configVersion < CONFIG_VERSION);
        
        if (needsUpgrade)
        {
            f.close();
            
            std::string versionInfo = "[CONFIG] Upgrading from version " + 
                                     std::to_string(configVersion) + 
                                     " to version " + 
                                     std::to_string(CONFIG_VERSION);
            Log(versionInfo);
            
            // Create backup with .old extension
            std::filesystem::path archivePath = configPath;
            std::wstring ext = L".old";
            archivePath += ext;
            
            try {
                std::filesystem::copy_file(configPath, archivePath, 
                                          std::filesystem::copy_options::overwrite_existing);
            } catch (...) {
                Log("Warning: Could not create config archive");
            }
            
			// Write upgraded configuration
			// Note: explorerConfig contains defaults at this point, which is exactly what we want for a fresh section
			WriteConfigurationFile(configPath, games, browsers, oldGames, gameWindows, browserWindows,
                                  ignoreNonInteractive, restoreOnExit, lockPolicy, 
                                  g_suspendUpdatesDuringGames.load(),
                                  g_idleRevertEnabled.load(),
                                  g_idleTimeoutMs.load(),
                                  explorerConfig);
            
            // Re-parse the upgraded file (prevent stack overflow with depth limit)
            static thread_local int upgradeDepth = 0;
            if (upgradeDepth < 2)
            {
                upgradeDepth++;
                LoadConfig(); 
                upgradeDepth--;
            }
            return;
        }

{
			std::unique_lock lg(g_setMtx);
            g_games = std::move(games);
            g_browsers = std::move(browsers);
            g_oldGames = std::move(oldGames);
			g_gameWindows = std::move(gameWindows);
            g_browserWindows = std::move(browserWindows);
            g_customLaunchers = std::move(customLaunchers);
            g_ignoredProcesses = std::move(ignoredProcesses);
        }
        
		g_ignoreNonInteractive.store(ignoreNonInteractive);
        g_restoreOnExit.store(restoreOnExit);
        g_lockPolicy.store(lockPolicy);
        
		// Finalize Explorer Config with Validations
        // Cross-validate with global idle settings
        if (explorerConfig.enabled && g_idleRevertEnabled.load()) {
            if (g_idleTimeoutMs.load() < explorerConfig.idleThresholdMs) {
                Log("[CONFIG] Forcing global idle_timeout to match explorer idle_threshold");
                g_idleTimeoutMs.store(explorerConfig.idleThresholdMs);
            }
        }

        // Enforce minimum thresholds
        if (explorerConfig.idleThresholdMs < 5000) {
             Log("[CONFIG] explorer.idle_threshold too low (<5s). Forcing to 15s.");
             explorerConfig.idleThresholdMs = 15000;
        }
        g_explorerBooster.UpdateConfig(explorerConfig);
        
		Log("Config loaded: " + std::to_string(g_games.size()) + " games, " +
            std::to_string(g_browsers.size()) + " browsers, " +
            std::to_string(g_oldGames.size()) + " legacy games, " +
            std::to_string(g_ignoredProcesses.size()) + " ignored, " +
            std::to_string(g_customLaunchers.size()) + " custom launchers, " +
            std::to_string(g_gameWindows.size()) + " game windows, " +
            std::to_string(g_browserWindows.size()) + " browser windows | " +
            "ignore_non_interactive=" + (ignoreNonInteractive ? "true" : "false") + " | " +
            "restore_on_exit=" + (restoreOnExit ? "true" : "false") + " | " +
            "lock_policy=" + (lockPolicy ? "true" : "false") + " | " +
            "idle_revert=" + (g_idleRevertEnabled.load() ? "true" : "false") + 
            "(" + std::to_string(g_idleTimeoutMs.load() / 1000) + "s) | " +
            "suspend_updates=" + (g_suspendUpdatesDuringGames.load() ? "true" : "false") + " | " +
            "smart_explorer=" + (explorerConfig.enabled ? "true" : "false"));
			
        // Debug log ignored processes
        Log("[CONFIG] Ignored processes list (" + std::to_string(g_ignoredProcesses.size()) + "):");
        for (const auto& proc : g_ignoredProcesses) {
            Log("  - " + WideToUtf8(proc.c_str()));
        }
    }
    catch (const std::exception& e)
    { 
        Log(std::string("LoadConfig exception: ") + e.what()); 
    }
}