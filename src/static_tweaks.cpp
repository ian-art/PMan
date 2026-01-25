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

#include "static_tweaks.h"
#include "utils.h"
#include "logger.h"
#include "restore.h"
#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <taskschd.h>
#include <comdef.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

// Define custom flag for Delayed Start since it's not a standard single API value
#ifndef SERVICE_DELAYED_AUTO_START
#define SERVICE_DELAYED_AUTO_START 0xFF000002
#endif

static std::wstring GetBackupDirectory()
{
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, path))) {
        std::filesystem::path p(path);
        p /= L"PriorityMgr";
        p /= L"Backups";
        std::filesystem::create_directories(p);
        return p.wstring();
    }
    return L"";
}

static void BackupRegistryKey(const std::wstring& keyName, const std::wstring& filename)
{
    std::wstring dir = GetBackupDirectory();
    if (dir.empty()) return;

    std::wstring fullPath = dir + L"\\" + filename;
    
    // Use reg.exe export for reliable backups
    // Format: reg export "HKLM\..." "C:\Path\file.reg" /y
    std::wstring cmd = L"reg.exe export \"" + keyName + L"\" \"" + fullPath + L"\" /y";
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    
    // Create mutable buffer
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);

    if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Log("[BACKUP] Exported " + WideToUtf8(keyName.c_str()));
    } else {
        Log("[BACKUP] Failed to export " + WideToUtf8(keyName.c_str()));
    }
}

static void PerformSafetyBackup()
{
    // Backup critical areas we are about to touch
    Log("[BACKUP] Starting registry backup before applying tweaks...");
    
    BackupRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl", L"PriorityControl.reg");
    BackupRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"MemoryMgmt.reg");
    BackupRegistryKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"MultimediaSysProfile.reg");
    BackupRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"TcpipParams.reg");
    BackupRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power", L"PowerControl.reg");
}

// --------------------------------------------------------------------------------
// AV-SAFE HELPER FUNCTIONS (Native API)
// --------------------------------------------------------------------------------

// Helper to safely set a DWORD registry value
static void ConfigureRegistry(HKEY root, const wchar_t* subkey, const wchar_t* valueName, DWORD data)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hKey);
    
    if (status != ERROR_SUCCESS) {
        status = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    }

    if (status == ERROR_SUCCESS) {
        status = RegSetValueExW(hKey, valueName, 0, REG_DWORD, 
                               reinterpret_cast<const BYTE*>(&data), sizeof(data));
        
        if (status == ERROR_SUCCESS) {
            Log("[TWEAK] Applied Registry: " + std::string(WideToUtf8(valueName)) + " = " + std::to_string(data));
        } else {
            Log("[TWEAK] Failed to set value: " + std::string(WideToUtf8(valueName)));
        }
        RegCloseKey(hKey);
    } else {
        Log("[TWEAK] Failed to open/create key: " + std::string(WideToUtf8(subkey)));
    }
}

// Helper to safely set a String registry value
static void ConfigureRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* valueName, const wchar_t* data)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hKey);
    
    if (status != ERROR_SUCCESS) {
        status = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    }

    if (status == ERROR_SUCCESS) {
        status = RegSetValueExW(hKey, valueName, 0, REG_SZ, 
                               reinterpret_cast<const BYTE*>(data), (DWORD)(wcslen(data) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

// Helper to safely set a Binary registry value
static void ConfigureRegistryBinary(HKEY root, const wchar_t* subkey, const wchar_t* valueName, const BYTE* data, DWORD size)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hKey);
    
    if (status != ERROR_SUCCESS) {
        status = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    }

    if (status == ERROR_SUCCESS) {
        status = RegSetValueExW(hKey, valueName, 0, REG_BINARY, data, size);
        RegCloseKey(hKey);
    }
}

// Helper to delete a registry value
static void DeleteRegistryValue(HKEY root, const wchar_t* subkey, const wchar_t* valueName)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hKey);
    
    if (status == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, valueName);
        RegCloseKey(hKey);
    }
}

// Helper to delete a registry key
static void DeleteRegistryKey(HKEY root, const wchar_t* subkey)
{
    RegDeleteKeyExW(root, subkey, KEY_WOW64_64KEY, 0);
}

// Helper to set service startup type
static void SetServiceStartup(const wchar_t* serviceName, DWORD startupType)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        Log("[ERROR] OpenSCManager failed: " + std::to_string(GetLastError()));
        return;
    }

    SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
    if (!service) {
        // Silent ignore for "Does not exist" to avoid log spam on different Windows versions
        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
            Log("[ERROR] Failed to open service " + std::string(WideToUtf8(serviceName)) + ": " + std::to_string(GetLastError()));
        }
        CloseServiceHandle(scm);
        return;
    }

    DWORD actualStartType = startupType;
    bool isDelayed = false;

    // Handle Delayed Auto Start Special Case
    if (startupType == SERVICE_DELAYED_AUTO_START) {
        actualStartType = SERVICE_AUTO_START;
        isDelayed = true;
    }

    // 1. Set the basic startup type
    if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, actualStartType, SERVICE_NO_CHANGE,
                           nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
    {
        // 2. Handle Delayed Auto-Start flag explicitly
        if (actualStartType == SERVICE_AUTO_START) {
            SERVICE_DELAYED_AUTO_START_INFO delayedInfo = { 0 };
            delayedInfo.fDelayedAutostart = isDelayed ? TRUE : FALSE;
            
            if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayedInfo)) {
                Log("[WARN] Failed to set Delayed flag for " + std::string(WideToUtf8(serviceName)));
            }
        }
        Log("[TWEAK] Service Configured: " + std::string(WideToUtf8(serviceName)));
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            Log("[ERROR] Access Denied configuring " + std::string(WideToUtf8(serviceName)));
        } else {
            Log("[ERROR] Failed to configure " + std::string(WideToUtf8(serviceName)) + ": " + std::to_string(err));
        }
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

// Helper to enumerate and configure dynamic user services (e.g. suffixes like _1a2b3)
static void EnumerateAndConfigureUserServices(const wchar_t* pattern, DWORD startupType)
{
    // RAII wrapper for SC_HANDLE to ensure closure on any return path
    class ScHandleGuard {
        SC_HANDLE h_;
    public:
        ScHandleGuard(SC_HANDLE h) : h_(h) {}
        ~ScHandleGuard() { if (h_) CloseServiceHandle(h_); }
        operator SC_HANDLE() const { return h_; }
        bool IsValid() const { return h_ != nullptr; }
    };

    ScHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
    if (!scm.IsValid()) {
        Log("[ERROR] OpenSCManager for enum failed: " + std::to_string(GetLastError()));
        return;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    std::vector<BYTE> buffer;

    // Loop to handle the race condition where service count changes between size check and data retrieval
    while (true) {
        // [FIX] Always reset resumeHandle when retrying; otherwise we miss the first N services
        resumeHandle = 0;
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded,
            &servicesReturned, &resumeHandle, nullptr)) {
            break;
        }

        DWORD error = GetLastError();
        if (error == ERROR_MORE_DATA) {
            buffer.resize(bytesNeeded + static_cast<DWORD>(buffer.size()));
        }
        else {
            Log("[ERROR] EnumServicesStatusExW failed: " + std::to_string(error));
            return;
        }
    }

    if (servicesReturned > 0 && !buffer.empty()) {
        if (buffer.size() < servicesReturned * sizeof(ENUM_SERVICE_STATUS_PROCESSW)) {
            return; 
        }

        auto* services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());
        size_t patternLen = wcslen(pattern);

        for (DWORD i = 0; i < servicesReturned; i++) {
            if (wcsncmp(services[i].lpServiceName, pattern, patternLen) == 0) {
                SetServiceStartup(services[i].lpServiceName, startupType);
            }
        }
    }
}

// [Removed local DisableScheduledTask to use shared implementation from utils.cpp]

// --------------------------------------------------------------------------------
// MAIN TWEAK LOGIC
// --------------------------------------------------------------------------------

bool ApplyStaticTweaks(const TweakConfig& config)
{
    // 1. Auto-Create Restore Point
    static bool s_sessionRestorePointCreated = false;

    if (!s_sessionRestorePointCreated)
    {
        Log("[SAFETY] Attempting to create System Restore point...");

        // Visual indication that the app is busy (prevents "is it broken?" panic)
        HCURSOR hOriginalCursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));
        bool rpSuccess = CreateRestorePoint();
        SetCursor(hOriginalCursor); // Restore cursor

        if (!rpSuccess) {
            int result = MessageBoxW(nullptr, 
                L"PMan failed to create an automatic System Restore point.\n\n"
                L"It is HIGHLY RECOMMENDED that you create one manually before proceeding.\n\n"
                L"Do you want to continue anyway?", 
                L"Safety Warning", MB_YESNO | MB_ICONWARNING | MB_TOPMOST);
            
            if (result == IDNO) {
                Log("[SAFETY] User aborted tweaks due to failed restore point.");
                return false;
            }
        }
        // Mark as done so we don't freeze the UI on subsequent applies
        s_sessionRestorePointCreated = true;
    }

    // 2. Registry Backup
    PerformSafetyBackup();

    Log("[TWEAKS] Applying static system optimizations...");

    // ============================================================================
    // NETWORK OPTIMIZATIONS
    // ============================================================================
    if (config.network) {
        Log("[TWEAK] Applying Network Optimizations...");
        
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", L"TcpAckFrequency", 1);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", L"TCPNoDelay", 1);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"NetworkThrottlingIndex", 0xFFFFFFFF);
    }

    // ============================================================================
    // SYSTEM RESPONSIVENESS
    // ============================================================================
    if (config.power) {
        Log("[TWEAK] Applying System Responsiveness tweaks...");
        
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"SystemResponsiveness", 0);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", L"GPU Priority", 8);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", L"Priority", 6);
        ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", L"Scheduling Category", L"High");

        // ============================================================================
        // KERNEL & MEMORY
        // ============================================================================
        Log("[TWEAK] Applying Kernel & Memory settings...");
        
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"LargeSystemCache", 0);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"DisablePagingExecutive", 1);
    }

    // ============================================================================
    // PRIVACY & TELEMETRY
    // ============================================================================
    if (config.privacy) {
    Log("[TWEAK] Applying Privacy & Telemetry settings...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement", L"ScoobeSystemSettingEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\DataCollection", L"DoNotShowFeedbackNotifications", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableTailoredExperiencesWithDiagnosticData", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\AdvertisingInfo", L"DisabledByGroupPolicy", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting", L"Disabled", 1);
    // Kill Cross-Device Resume background agent
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\CrossDeviceResume\\Configuration", L"IsResumeAllowed", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Siuf\\Rules", L"NumberOfSIUFInPeriod", 0);
    DeleteRegistryValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Siuf\\Rules", L"PeriodInNanoSeconds");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Siuf\\Rules", L"NumberOfSIUFInPeriod", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Siuf\\Rules", L"PeriodInNanoSeconds", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\AppCompat", L"DisableInventory", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\AppCompat", L"AITEnable", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Search", L"AllowSearchToUseLocation", 0);
    }

    // ============================================================================
    // CONTENT DELIVERY / ADS / SUGGESTIONS
    // ============================================================================
    if (config.privacy) {
    Log("[TWEAK] Applying Content Delivery & Ads blocking...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"RotatingLockScreenEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"RotatingLockScreenOverlayEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SilentInstalledAppsEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-338387Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-338393Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-310093Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SoftLandingEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SystemPaneSuggestionsEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"ContentDeliveryAllowed", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"FeatureManagementEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"OemPreInstalledAppsEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"PreInstalledAppsEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"PreInstalledAppsEverEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SlideshowEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-338388Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-88000326Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContentEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-338389Enabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", L"SubscribedContent-353698Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\PushToInstall", L"DisablePushToInstall", 1);
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\Subscriptions");
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\SuggestedApps");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableWindowsConsumerFeatures", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableSoftLanding", 1);
    }

    // ============================================================================
    // EXPLORER & UI BEHAVIOR
    // ============================================================================
    if (config.explorer) {
    Log("[TWEAK] Applying Explorer & UI Behavior tweaks...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowSyncProviderNotifications", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Hidden", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowSuperHidden", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"HideIcons", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"HideFileExt", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"NavPaneExpandToCurrentFolder", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"NavPaneShowAllFolders", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"SeparateProcess", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"DesktopProcess", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"LaunchTo", 1);
    // [FIX] REMOVED: Forcing Explorer to dGPU causes visual glitches (black start menu squares) on Hybrid Graphics systems.
	// ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences", L"C:\\Windows\\explorer.exe", L"GpuPreference=2;");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\UnsupportedHardwareNotificationCache", L"SV2", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\UnsupportedHardwareNotificationCache", L"SV1", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"IgnorePerProcessSystemDPIToast", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize", L"StartupDelayInMSec", 0);
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"\\*\\shellex\\ContextMenuHandlers\\EPP");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Drive\\shellex\\ContextMenuHandlers\\EPP");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Directory\\shellex\\ContextMenuHandlers\\EPP");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"CLSID\\{09A47860-11B0-4DA5-AFA5-26D86198A780}");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", L"VisualFXSetting", 3);
    BYTE userPrefMask[] = {0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00};
    ConfigureRegistryBinary(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"UserPreferencesMask", userPrefMask, sizeof(userPrefMask));
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop\\WindowMetrics", L"MinAnimate", L"0");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"TaskbarAnimations", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"DisablePreviewDesktop", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", L"EnableAeroPeek", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", L"AlwaysHibernateThumbnails", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"IconsOnly", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ListviewAlphaSelect", 1);
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"DragFullWindows", L"0");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"FontSmoothingType", 2);
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"FontSmoothing", L"2");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ListviewShadow", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", L"ListBoxSmoothScrolling", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", L"ToastEnabled", 0);
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"LowLevelHooksTimeout", L"1000");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoLowDiskSpaceChecks", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"LinkResolveIgnoreLinkInfo", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoResolveSearch", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoResolveTrack", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoInternetOpenWith", 1);
    DeleteRegistryValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"WindowsWelcomeCenter");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"DisallowShaking", 1);
    DeleteRegistryKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{98D99750-0B8A-4c59-9151-589053683D73}");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel", L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\ClassicStartMenu", L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications", L"GlobalUserDisabled", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications", L"Disabled", 1);
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L".bmp\\ShellNew");
    ConfigureRegistryString(HKEY_CLASSES_ROOT, L".cmd\\ShellNew", L"NullFile", L"");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Start_ShowRun", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Start_TrackProgs", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"EnableTransparency", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"SystemUsesLightTheme", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\OperationStatusManager", L"EnthusiastMode", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowTaskViewButton", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People", L"PeopleBand", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"TaskbarGlomLevel", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"PeopleBand", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"TaskbarMn", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"HideSCAMeetNow", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"AutoEndTasks", 1);
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags");
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\AllFolders\\Shell", L"FolderType", L"NotSpecified");
    }

    // ============================================================================
    // PERFORMANCE & MEMORY MANAGEMENT
    // ============================================================================
    if (config.power) {
    Log("[TWEAK] Applying Performance & Memory Management tweaks...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"DisablePagingExecutive", 1);
    // [FIX] LargeSystemCache=1 is detrimental to interactive desktop/gaming performance. 
    // It steals RAM for file caching, starving network drivers and apps.
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"LargeSystemCache", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnablePrefetcher", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnableSuperfetch", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnableBootTrace", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"SfTracingState", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"SwapfileControl", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"SystemResponsiveness", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"NetworkThrottlingIndex", 4294967295);

    // SvcHost Collapse: Force service grouping by raising split threshold to Total RAM
    MEMORYSTATUSEX statex = { sizeof(statex) };
    if (GlobalMemoryStatusEx(&statex)) {
        // Formula: Total Physical RAM in KB
        DWORD totalRamKB = static_cast<DWORD>(statex.ullTotalPhys / 1024);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", L"SvcHostSplitThresholdInKB", totalRamKB);
        Log("[TWEAK] SvcHost Collapse applied. Threshold set to: " + std::to_string(totalRamKB) + " KB");
    }
    }
    
    // ============================================================================
    // NETWORK & TCP/IP
    // ============================================================================
    if (config.network) {
    Log("[TWEAK] Applying Network & TCP/IP tweaks...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tcpip6\\Parameters", L"DisabledComponents", 32);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"DefaultTTL", 100);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"IRPStackSize", 32);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SizReqBuf", 95268);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\Psched", L"NonBestEffortLimit", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanmanServer\\parameters", L"AutoShareWks", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"AutoShareServer", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Ndu", L"Start", 4);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"IRPStackSize", 30);
    }

    // ============================================================================
    // GRAPHICS & DWM
    // ============================================================================
    if (config.power) {
    Log("[TWEAK] Applying Graphics & DWM settings...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\GraphicsDrivers", L"HwSchMode", 2);

    // ============================================================================
    // POWER & BOOT
    // ============================================================================
    Log("[TWEAK] Applying Power & Boot settings...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\BootControl", L"BootProgressAnimation", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Citrix", L"EnableVisualEffect", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\94d3a615-a899-4ac5-ae2b-e4d8f634367f", L"Attributes", 1);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control", L"WaitToKillServiceTimeout", L"1000");
    }

    // ============================================================================
    // SECURITY POLICIES
    // ============================================================================
    if (config.privacy) {
    Log("[TWEAK] Applying Security Policies...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"Negotiate", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential", 0);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows NT\\MitigationOptions", L"MitigationOptions_FontBocking", L"1000000000000");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"PromptOnSecureDesktop", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", 5);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorEnhancedAdmin", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorUser", 3);
    }

	// ============================================================================
    // LOCATION SERVICES (System-wide Disable)
    // ============================================================================
    if (config.location) {
    Log("[TWEAK] Applying Location Services disabling...");

    // 1. Disable Location & Sensors via Policy
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\LocationAndSensors", L"DisableLocation", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\LocationAndSensors", L"DisableLocationScripting", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\LocationAndSensors", L"DisableSensors", 1);

    // 2. Disable App Access to Location (Policy)
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\AppPrivacy", L"LetAppsAccessLocation", 2);

    // 3. Deny Capability Access (Global Consent Store)
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location", L"Value", L"Deny");

    // 4. Deny Capability Access (Current User Consent Store)
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location", L"Value", L"Deny");

    // 5. Force Disable Geolocation Service (lfsvc)
    // Note: SERVICE_DISABLED = 4
    // SetServiceStartup(L"lfsvc", SERVICE_DISABLED);
    }

    // ============================================================================
    // SYSTEM TWEAKS (MISC)
    // ============================================================================
    if (config.explorer) {
    Log("[TWEAK] Applying System Miscellaneous tweaks...");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"Max Cached Icons", L"8192");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme", 0);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"Path", L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy", L"Unrestricted");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"Path", L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy", L"Unrestricted");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\ContentIndex", L"FilterFilesWithUnknownExtensions", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\FileSystem", L"NtfsDisableLastAccessUpdate", 0);
    // PnPCapabilities for network adapters
    for (int i = 0; i <= 30; i++) {
        wchar_t subkey[256];
        swprintf_s(subkey, L"System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%04d", i);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, subkey, L"PnPCapabilities", 24);
    }
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Setup", L"SourcePath", L"");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", L"RegDone", L"1");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Command Processor", L"CompletionChar", 9);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\EnhancedStorageDevices", L"TCGSecurityActivationDisabled", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\NcdAutoSetup\\Private", L"AutoSetup", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\System", L"EnableCdp", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\MicrosoftEdge\\Main", L"AllowPrelaunch", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Edge", L"HideFirstRunExperience", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\MiscPolicyInfo", L"ShippedWithReserves", 2);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\PassedPolicy", L"ShippedWithReserves", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\ReserveManager", L"ShippedWithReserves", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Office\\16.0\\common\\officeupdate", L"preventteamsinstall", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\WindowsUpdate\\UX\\Settings", L"FlightSettingsMaxPauseDays", 730);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\Windows Search", L"BingSearchEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Search", L"BingSearchEnabled", 0);
    // Disable non-policy Bing Search and CrossDeviceResume (Timeline)
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Search", L"BingSearchEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", L"NoTileApplicationNotification", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", L"SensorPermissionState", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration", L"Status", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config", L"DODownloadMode", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization", L"DODownloadMode", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowFullControl", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\FileSystem", L"LongPathsEnabled", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\Windows Feeds", L"EnableFeeds", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Feeds", L"ShellFeedsTaskbarViewMode", 2);
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}");
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", L"System.IsPinnedToNameSpaceTree", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\CloudContent\\DisableWindowsConsumerFeatures", L"", 1);
	ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32", L"", L"");
    }

    // ============================================================================
    // NETWORK DISCIPLINE
    // ============================================================================
    if (config.network) {
    Log("[TWEAK] Applying Network Discipline...");
    // Disable automatic discovery of network folders and printers (NoNetCrawling)
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"NoNetCrawling", 1);
    }

    // ============================================================================
    // TELEMETRY TASKS
    // ============================================================================
    if (config.privacy) {
        Log("[TWEAK] Suppressing Telemetry Scheduled Tasks...");
    const std::vector<std::wstring> telemetryTasks = {
        L"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        L"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        L"Microsoft\\Windows\\Autochk\\Proxy",
        L"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        L"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        L"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
        L"Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
        L"Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
        L"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
        
        // Dead Zone Triggers
        L"Microsoft\\Windows\\Maps\\MapsUpdateTask",
        L"Microsoft\\Windows\\Maps\\MapsToastTask",

        // Application Experience (The "Mare" & "Pca" group)
        L"Microsoft\\Windows\\Application Experience\\MareBackup",
        L"Microsoft\\Windows\\Application Experience\\StartupAppTask",
        L"Microsoft\\Windows\\Application Experience\\PcaPatchDbTask"
    };

    for (const auto& task : telemetryTasks) {
        DisableScheduledTask(task);
    }
    }

    // ============================================================================
    // POLICY & PERSISTENCE (AV-SAFE)
    // ============================================================================
    if (config.privacy) {
    Log("[TWEAK] Applying Policy & Persistence...");

    // 1. Update Deferral (Not Disabling)
    // AUOptions = 2 (Notify for download and auto install). Gives user control without breaking OS.
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"AUOptions", 2);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"NoAutoUpdate", 0);
    // Exclude drivers from quality updates to prevent stability issues (User consented stability)
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"ExcludeWUDriversInQualityUpdate", 1);

    // 2. Delivery Optimization Limits
    // DODownloadMode = 0 (HTTP Only, no P2P). Reduces background upload/download bandwidth.
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization", L"DODownloadMode", 0);
    }
    
    // 3. Power Profile Tuning (Unhide Advanced Settings for User Tuning)
    if (config.power) {
    // Processor Idle Demotion Threshold
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\4b92d758-5a24-4851-a470-815d78aee119", L"Attributes", 2);
    // Processor Idle Promote Threshold
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\7b224883-b3cc-4d79-819f-8374152cbe7c", L"Attributes", 2);
    // Latency Sensitivity Hint (Unhide)
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\619b7505-003b-4e82-b7a6-4dd29c300971", L"Attributes", 2);
    }

    // ============================================================================
    // UWP / BACKGROUND TASKS
    // ============================================================================
    if (config.bloatware) {
	Log("[TWEAK] Applying UWP & Background Tasks cleanup...");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy");
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder", L"Attributes", 0x903a0004);
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder", L"Attributes", 0x903a0004);
    }

    // ============================================================================
    // GAME DVR & XBOX
    // ============================================================================
    if (config.dvr) {
    Log("[TWEAK] Applying Game DVR & Xbox disabling...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR", L"AppCaptureEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"System\\GameConfigStore", L"GameDVR_Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\GameDVR", L"AllowGameDVR", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR", L"value", 0);
    }

    // ============================================================================
    // FILE ASSOCIATIONS (HTA)
    // ============================================================================
    if (config.explorer) {
    Log("[TWEAK] Applying File Associations...");
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.hta\\OpenWithProgids", L"htafile", L"");

    // ============================================================================
    // REMOVE PIN TO QUICKACCES IN RECYCLEBIN
    // ============================================================================
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\Folder\\shell\\pintohome", L"AppliesTo", L"System.ParsingName:<>\"::{645FF040-5081-101B-9F08-00AA002F954E}\"");
    }

	// ============================================================================
	// WINDOWS SERVICES CONFIGURATION
	// ============================================================================
    if (config.services) {
	Log("[TWEAK] Configuring Windows Services (Set to Manual)...");

    // List of services to set to DEMAND_START (Manual).
    // Note: User-pattern services (ending in *) are handled separately.
    const std::vector<std::wstring> serviceList = {
        L"AJRouter", L"ALG", L"AppIDSvc", L"AppMgmt", L"AppReadiness", L"AppVClient", L"AppXSvc", L"Appinfo", 
        L"AssignedAccessManagerSvc", L"AxInstSV", L"BDESVC", 
        L"BFE", L"BITS", L"BTAGService", L"BrokerInfrastructure", L"Browser", L"BthAvctpSvc", L"BthHFSrv", 
        L"CDPSvc", L"COMSysApp", L"CertPropSvc", L"ClipSVC", L"CoreMessagingRegistrar", L"CryptSvc", L"CscService", 
        L"DPS", L"DcomLaunch", L"DcpSvc", L"DevQueryBroker", L"DeviceAssociationService", L"DeviceInstall", 
        L"Dhcp", /* L"DiagTrack" (Disabled below), */ L"DialogBlockingService", L"DispBrokerDesktopSvc", L"DisplayEnhancementService", 
        L"DmEnrollmentSvc", L"Dnscache", L"EFS", L"EapHost", L"EntAppSvc", L"EventLog", L"EventSystem", 
        L"FDResPub", L"Fax", L"FontCache", L"FrameServer", L"FrameServerMonitor", L"GraphicsPerfSvc", 
        L"HomeGroupListener", L"HomeGroupProvider", L"HvHost", L"IEEtwCollectorService", L"IKEEXT", 
        L"InstallService", L"InventorySvc", L"IpxlatCfgSvc", L"KeyIso", L"KtmRm", L"LSM", L"LanmanServer", 
        L"LanmanWorkstation", L"LicenseManager", L"LxpSvc", L"MSDTC", L"MSiSCSI", L"MapsBroker", 
        L"McpManagementService", L"MicrosoftEdgeElevationService", L"MixedRealityOpenXRSvc", L"MpsSvc", 
        L"MsKeyboardFilter", L"NaturalAuthentication", L"NcaSvc", L"NcbService", L"NcdAutoSetup", L"NetSetupSvc", 
        L"NetTcpPortSharing", L"Netlogon", L"Netman", L"NgcCtnrSvc", L"NgcSvc", L"NlaSvc", L"PNRPAutoReg", 
        L"PNRPsvc", L"PcaSvc", L"PeerDistSvc", L"PerfHost", L"PhoneSvc", L"PolicyAgent",
        L"PrintNotify", L"ProfSvc", L"PushToInstall", L"QWAVE", L"RasAuto", L"RasMan", L"RemoteAccess", 
        L"RemoteRegistry", L"RetailDemo", L"RmSvc", L"RpcEptMapper", L"RpcLocator", L"RpcSs", L"SCPolicySvc", 
        L"SCardSvr", L"SDRSVC", L"SEMgrSvc", L"SENS", L"SNMPTRAP", L"SNMPTrap", L"SSDPSRV", L"SamSs", 
        L"ScDeviceEnum", L"Schedule", L"SecurityHealthService", L"Sense", L"SensorDataService", L"SensorService", 
        L"SensrSvc", L"SessionEnv", L"SharedAccess", L"SharedRealitySvc", L"ShellHWDetection", L"SmsRouter", 
        L"Spooler", L"SstpSvc", L"StiSvc", L"StorSvc", L"SysMain", L"SystemEventsBroker", L"TabletInputService", 
        L"TapiSrv", L"TermService", L"Themes", L"TieringEngineService", L"TimeBroker", L"TimeBrokerSvc", 
        L"TokenBroker", L"TrkWks", L"TroubleshootingSvc", L"TrustedInstaller", L"UI0Detect", L"UevAgentService", 
        L"UmRdpService", L"UserManager", L"UsoSvc", L"VGAuthService", L"VMTools", L"VSS", L"VacSvc", L"VaultSvc", 
        L"W32Time", L"WEPHOSTSVC", L"WFDSConMgrSvc", L"WMPNetworkSvc", L"WManSvc", L"WPDBusEnum", L"WSService", 
        L"WSearch", L"WaaSMedicSvc", L"WalletService", L"WarpJITSvc", L"WbioSrvc", L"Wcmsvc", L"WcsPlugInService", 
        L"WdNisSvc", L"WdiServiceHost", L"WdiSystemHost", L"WebClient", L"Wecsvc", L"WerSvc", L"WiaRpc", 
        L"WinDefend", L"WinHttpAutoProxySvc", L"WinRM", L"Winmgmt", L"WpcMonSvc", L"WpnService", 
        L"XblAuthManager", L"XblGameSave", L"XboxGipSvc", L"XboxNetApiSvc", L"autotimesvc", L"bthserv", 
        L"camsvc", L"cloudidsvc", L"dcsvc", L"defragsvc", L"diagnosticshub.standardcollector.service", 
        L"diagsvc", /* L"dmwappushservice" (Disabled below), */ L"dot3svc", L"edgeupdate", L"edgeupdatem", L"embeddedmode", L"fdPHost", 
        L"fhsvc", L"gpsvc", L"hidserv", L"icssvc", L"iphlpsvc", L"lfsvc", L"lltdsvc", L"lmhosts", L"mpssvc", 
        L"msiserver", L"netprofm", L"nsi", L"p2pimsvc", L"p2psvc", L"perceptionsimulation", L"pla", L"seclogon", 
        L"shpamsvc", L"smphost", L"spectrum", L"sppsvc", L"ssh-agent", L"svsvc", L"swprv", L"tiledatamodelsvc", 
        L"tzautoupdate", L"uhssvc", L"upnphost", L"vds", L"vm3dservice", L"vmicguestinterface", L"vmicheartbeat", 
        L"vmickvpexchange", L"vmicrdv", L"vmicshutdown", L"vmictimesync", L"vmicvmsession", L"vmicvss", L"vmvss", 
        L"wbengine", L"wcncsvc", L"webthreatdefsvc", L"wercplsupport", L"wisvc", L"wlidsvc", L"wlpasvc", 
        L"wmiApSrv", L"workfolderssvc", L"wscsvc", L"wuauserv", L"wudfsvc"
    };

    // Apply Manual start (SERVICE_DEMAND_START) to standard services
    for (const auto& svc : serviceList) {
        SetServiceStartup(svc.c_str(), SERVICE_DEMAND_START);
    }

    // Dead Zone: Explicitly disable specific telemetry/tracking services
    const std::vector<std::wstring> disabledServices = {
        L"DiagTrack",           // Connected User Experiences and Telemetry
        L"dmwappushservice"     // WAP Push Message Routing Service
    };
    for (const auto& svc : disabledServices) {
        SetServiceStartup(svc.c_str(), SERVICE_DISABLED);
    }

	// --- Pattern-based per-user service handling (Manual) ---
	const wchar_t* userServicePatterns[] = {
        L"BcastDVRUserService_",
        L"BluetoothUserService_",
        L"CDPUserSvc_",
        L"CaptureService_",
        L"ConsentUxUserSvc_",
        L"CredentialEnrollmentManagerUserSvc_",
        L"DeviceAssociationBrokerSvc_",
        L"DevicePickerUserSvc_",
        L"DevicesFlowUserSvc_",
        L"MessagingService_",
        L"NPSMSvc_",
        L"OneSyncSvc_",
        L"P9RdrService_",
        L"PenService_",
        L"PimIndexMaintenanceSvc_",
        L"PrintWorkflowUserSvc_",
        L"UdkUserSvc_",
        L"UnistoreSvc_",
        L"UserDataSvc_",
        L"WpnUserService_",
        L"cbdhsvc_",
        L"webthreatdefusersvc_"
	};

	for (const wchar_t* pattern : userServicePatterns) {
        // Strict adherence to "Minimal" spec: All services set to Manual, no exceptions.
		EnumerateAndConfigureUserServices(pattern, SERVICE_DEMAND_START);
	}
    }

	Log("[TWEAK] System optimizations applied successfully.");
    Log("*********************************");
    return true;
}
