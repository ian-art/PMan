#ifndef PMAN_CONSTANTS_H
#define PMAN_CONSTANTS_H

#include <windows.h>

// Config
static constexpr wchar_t CONFIG_FILENAME[] = L"config.ini";
static constexpr int CONFIG_VERSION = 1; // Increment when config structure changes

// Registry Values
static constexpr DWORD   VAL_GAME   = 0x28;
static constexpr DWORD   VAL_BROWSER= 0x26;
static constexpr DWORD   IOCP_SHUTDOWN_KEY = 0xFFFFFFFF;

// Mutex and Event Names
static constexpr wchar_t MUTEX_NAME[] = L"Global\\PriorityManager_Mutex_1F4E7D2A";
static constexpr wchar_t SHUTDOWN_EVENT_NAME[] = L"Global\\PriorityManager_Shutdown_Event_1F4E7D2A";

// Multimedia Class Scheduler Service (MMCSS) task types
static constexpr wchar_t MMCSS_TASK_GAMES[] = L"Games";
static constexpr wchar_t MMCSS_TASK_AUDIO[] = L"Pro Audio";
static constexpr wchar_t MMCSS_TASK_DISPLAY[] = L"DisplayPostProcessing";

// Kernel Process GUID for ETW
static const GUID KernelProcessGuid = 
    { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

// Undocumented API Constants
enum class UndocumentedApi : DWORD {
    ProcessGpuPriority = 82,
    ThreadBasePriority = 3
};

// Default config template
static constexpr const char* DEFAULT_CONFIG = R"(; Priority Manager Configuration by Ian Anthony Tancinco
; Auto-generated config file
; 
; Add executable names (lowercase) to each section
; Changes are detected automatically - no restart needed!
;
; Registry values:
;   Games:    0x28 - Optimized for consistent frame times
;   Browsers: 0x26 - Optimized for multitasking responsiveness

[meta]
version=1

[global]
; Ignore non-interactive processes (services, scheduled tasks, SYSTEM processes)
; This prevents background processes from triggering policy changes
ignore_non_interactive = true

; Restore original Win32PrioritySeparation value when program exits
; Prevents "stuck mode" after crashes or uninstall
restore_on_exit = true

; Lock policy against external interference (other tweaking tools)
; When enabled, automatically re-asserts our setting if another tool changes it
; WARNING: May conflict with other system optimization tools
lock_policy = false

; Suspend Windows Update and background transfers during gaming
; Reduces CPU/disk/network interference for better performance
; Services automatically resume when exiting game
suspend_updates_during_games = false

; Automatically revert to Browser Mode if system is idle for specified time
; and no game is currently running.
; Formats: 5m (minutes), 300s (seconds). Default: 5m
; no suffix = minutes: 5 (minutes)
idle_revert_enabled = true
idle_timeout = 5m

[games]
; Add your game executables here (one per line)
; Examples:
; game.exe
; eldenring.exe
; cyberpunk2077.exe
; leagueoflegends.exe

[browsers]
; Add browser executables here
chrome.exe
firefox.exe
msedge.exe
brave.exe
opera.exe
vivaldi.exe

[game_windows]
; ==================== WINDOW CLASS/TITLE DETECTION ====================
; These patterns help detect games BEFORE their process name appears
; The system checks both window titles AND window class names
; Matches are case-insensitive and use partial matching (contains)
; This is especially useful for:
;   - Games that launch through launchers
;   - Games with generic process names
;   - Games that show splash screens first
;
; HOW TO FIND WINDOW CLASS NAMES:
; 1. Download "Spy++" (comes with Visual Studio) or "Window Detective"
; 2. Launch your game
; 3. Use the finder tool to inspect the game window
; 4. Copy the "Class" or "ClassName" value
; 5. Add it here (one per line)

; ==================== GAME ENGINE WINDOW CLASSES ====================
; Unity Engine (very common - used by thousands of games)
UnityWndClass

; Unreal Engine (Fortnite, Valorant, PUBG, ARK, etc.)
UnrealWindow

; CryEngine (Crysis, Star Citizen, Hunt: Showdown)
CryENGINE

; Source Engine (Valve games - CS, Portal, L4D, TF2)
Valve001
SDL_app

; Godot Engine
Godot_EngineWindow

; GameMaker Studio
YoYo_GameMaker

; RPG Maker
RGSS Player

; ==================== GRAPHICS API WINDOW CLASSES ====================
; SDL (Simple DirectMedia Layer - many indie games)
SDL_app
SDL_Window

; GLFW (OpenGL Framework - Minecraft Java, indie games)
GLFW30

; ==================== SPECIFIC GAME LAUNCHERS ====================
; Electronic Arts
EAGLWindowClass

; Rockstar Games (GTA, RDR)
grcWindow

; Riot Games (League, Valorant)
RiotWindow

; Blizzard (WoW, Overwatch, Diablo)
GxWindowClass

; Bethesda Games
BSWindowClass

; ==================== POPULAR GAMES BY TITLE/CLASS ====================
; Add specific games you play
; Minecraft
Minecraft

; Roblox
ROBLOX

; Fortnite
FortniteClient

; League of Legends
LeagueClient

; World of Warcraft
World of Warcraft

; Counter-Strike
Counter-Strike

; Dota 2
Dota 2

; Apex Legends
Apex Legends

; Call of Duty
Call of Duty

; Grand Theft Auto
Grand Theft Auto

; Cyberpunk 2077
Cyberpunk 2077

; Elden Ring
ELDEN RING

; Baldur's Gate 3
Baldur's Gate 3

; Starfield
Starfield

; Path of Exile
Path of Exile

; Genshin Impact
Genshin Impact

; Final Fantasy XIV
FINAL FANTASY XIV

; Monster Hunter
Monster Hunter

; Terraria
Terraria

; Stardew Valley
Stardew Valley

; Valheim
Valheim

; Satisfactory
Satisfactory

; Factorio
Factorio

; Cities Skylines
Cities: Skylines

; Civilization
Sid Meier's Civilization

; Hollow Knight
Hollow Knight

; Hades
Hades

; Subnautica
Subnautica

; Lethal Company
Lethal Company

; Phasmophobia
Phasmophobia

; Helldivers 2
HELLDIVERS 2

; Resident Evil
RESIDENT EVIL

; Sekiro
Sekiro

; Dark Souls
DARK SOULS

; Doom
DOOM

; Half-Life
Half-Life

; Portal
Portal

; Witcher
The Witcher

; Fallout
Fallout

; Skyrim
Skyrim

; ==================== EMULATORS ====================
; RetroArch
RetroArch

; Dolphin (GameCube/Wii)
Dolphin

; PCSX2 (PS2)
PCSX2

; RPCS3 (PS3)
RPCS3

; Cemu (Wii U)
Cemu

; Yuzu (Switch)
yuzu

; PPSSPP (PSP)
PPSSPPWnd

; ==================== VR HEADSET SOFTWARE ====================
; SteamVR
SteamVR

; Oculus
OculusHome

; ==================== NOTES ====================
; - Patterns are case-insensitive
; - Partial matches work (e.g., "Unity" matches "UnityWndClass")
; - Add your specific games
; - Window class names are more reliable than titles
; - Check log file at C:\ProgramData\PriorityMgr\log.txt

[browser_windows]
; ==================== BROWSER WINDOW CLASS DETECTION ====================
; These patterns detect browsers by their window class names
; Useful for embedded browsers or processes with generic names

; ==================== CHROMIUM-BASED BROWSERS ====================
; Google Chrome, Edge, Brave, Opera, Vivaldi, Arc, etc.
Chrome_WidgetWin_0
Chrome_WidgetWin_1
Chrome_WidgetWin_2
Chrome_RenderWidgetHostHWND

; ==================== FIREFOX-BASED BROWSERS ====================
; Mozilla Firefox, Waterfox, LibreWolf, Pale Moon, Tor Browser
MozillaWindowClass
MozillaUIWindowClass

; ==================== INTERNET EXPLORER / EDGE LEGACY ====================
; Internet Explorer (old)
IEFrame

; Microsoft Edge Legacy (pre-Chromium)
ApplicationFrameWindow

; ==================== EMBEDDED BROWSERS ====================
; CEF (Chromium Embedded Framework)
CefBrowser

; Electron (Discord, VS Code, Slack, etc.)
Chrome_WidgetWin_1

; Qt WebEngine
Qt5QWindowIcon

; Windows WebView2
WebView2

; ==================== SPECIFIC BROWSERS ====================
; Opera / Opera GX
OperaWindow

; Yandex Browser
YandexBrowser

; Safari (rare on Windows)
Safari

; ==================== WINDOW TITLE PATTERNS ====================
; Common browser title patterns (less reliable than class names)
Google Chrome
Mozilla Firefox
Microsoft Edge
- Opera
- Brave
- Vivaldi

; ==================== EMBEDDED BROWSER CONTEXTS ====================
; Steam In-Game Browser/Overlay (if you want it in browser mode)
; vguiPopupWindow
; Steam

; Discord (if you want it in browser mode, not game mode)
; Discord
; Chrome_WidgetWin_1

; Spotify (Electron app with browser-like behavior)
; Chrome_WidgetWin_1
; Spotify

; Slack (Electron app)
; Chrome_WidgetWin_1
; Slack

; Microsoft Teams (Electron app)
; Chrome_WidgetWin_1
; Teams

; ==================== NOTES ====================
; - Browser window classes are more consistent than titles
; - Many modern browsers use Chrome_WidgetWin_1 (Chromium-based)
; - Firefox variants use MozillaWindowClass
; - Electron apps use Chromium underneath
; - Embedded WebViews in apps may trigger browser mode
; - If you use Discord/Slack while gaming, DON'T add them here
; - Test by opening browsers and checking the log file
; - Case-insensitive partial matching is used
; - Less is more - only add browsers you actually use
; - All names should be in lowercase
; - Remove .exe names you don't use to keep config clean
; - Add your specific games/browsers if not listed
; - Check log at: C:\ProgramData\PriorityMgr\log.txt
; ================= END OF CONFIG =================
)";

#endif // PMAN_CONSTANTS_H