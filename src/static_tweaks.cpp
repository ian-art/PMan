#include "static_tweaks.h"
#include "logger.h"
#include "utils.h"
#include <windows.h>
#include <string>
#include <vector>

// --------------------------------------------------------------------------------
// AV-SAFE HELPER FUNCTIONS (Native API)
// --------------------------------------------------------------------------------

// Helper to safely set a DWORD registry value
static void ConfigureRegistry(HKEY root, const wchar_t* subkey, const wchar_t* valueName, DWORD data)
{
    HKEY hKey = nullptr;
    // KEY_SET_VALUE access only
    LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hKey);
    
    // Create key if missing
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

// Helper to delete a registry key (simplified - requires recursion for keys with subkeys)
static void DeleteRegistryKey(HKEY root, const wchar_t* subkey)
{
    // Note: This is a simplified version. Full implementation would recursively delete subkeys.
    RegDeleteKeyExW(root, subkey, KEY_WOW64_64KEY, 0);
}

// Helper to set service startup type
static void SetServiceStartup(const wchar_t* serviceName, DWORD startupType)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
        if (service) {
            if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, startupType, SERVICE_NO_CHANGE,
                               nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
            {
                Log("[TWEAK] Service Configured: " + std::string(WideToUtf8(serviceName)));
            }
            else
            {
                // Optional: Log failure if needed, usually Access Denied if not Admin
            }
            CloseServiceHandle(service);
        }
CloseServiceHandle(scm);
    }
}

// Helper to enumerate and configure dynamic user services (e.g. suffixes like _1a2b3)
static void EnumerateAndConfigureUserServices(const wchar_t* pattern, DWORD startupType)
{
    // Request ENUMERATE permission
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    void* buf = nullptr;
    DWORD bufSize = 0;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // First call to determine required buffer size
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                         nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (GetLastError() == ERROR_MORE_DATA) {
        bufSize = bytesNeeded;
        buf = malloc(bufSize);
        if (buf) {
            // Second call to get actual data
            if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                                     reinterpret_cast<LPBYTE>(buf), bufSize, &bytesNeeded, 
                                     &servicesReturned, &resumeHandle, nullptr)) {
                
                LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buf);
                size_t patternLen = wcslen(pattern);

                for (DWORD i = 0; i < servicesReturned; i++) {
                    // Check if service name starts with the pattern (prefix match)
                    if (wcsncmp(services[i].lpServiceName, pattern, patternLen) == 0) {
                        // Reuse existing helper to configure and log
                        SetServiceStartup(services[i].lpServiceName, startupType);
                    }
                }
            }
            free(buf);
        }
    }
    CloseServiceHandle(scm);
}

// --------------------------------------------------------------------------------
// MAIN TWEAK LOGIC
// --------------------------------------------------------------------------------

void ApplyStaticTweaks()
{
    Log("*********************************");
    Log("[TWEAK] Starting Manual System Optimization...");

    // ============================================================================
    // NETWORK OPTIMIZATIONS
    // ============================================================================
    Log("[TWEAK] Applying Network Optimizations...");
    
    // Disable Nagle's Algorithm (TcpAckFrequency/TCPNoDelay)
    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", 
        L"TcpAckFrequency", 1);
    
    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", 
        L"TCPNoDelay", 1);

    // Network Throttling Index
    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", 
        L"NetworkThrottlingIndex", 0xFFFFFFFF);

    // ============================================================================
    // SYSTEM RESPONSIVENESS
    // ============================================================================
    Log("[TWEAK] Applying System Responsiveness tweaks...");
    
    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", 
        L"SystemResponsiveness", 0);

    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", 
        L"GPU Priority", 8);

    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", 
        L"Priority", 6);

    ConfigureRegistryString(HKEY_LOCAL_MACHINE, 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games", 
        L"Scheduling Category", L"High");

    // ============================================================================
    // KERNEL & MEMORY
    // ============================================================================
    Log("[TWEAK] Applying Kernel & Memory settings...");
    
    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 
        L"LargeSystemCache", 0);

    ConfigureRegistry(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 
        L"DisablePagingExecutive", 1);

    // ============================================================================
    // PRIVACY & TELEMETRY
    // ============================================================================
    Log("[TWEAK] Applying Privacy & Telemetry settings...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement", L"ScoobeSystemSettingEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", L"AllowTelemetry", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"DoNotShowFeedbackNotifications", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableTailoredExperiencesWithDiagnosticData", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", L"DisabledByGroupPolicy", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", L"Disabled", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Siuf\\Rules", L"NumberOfSIUFInPeriod", 0);
    DeleteRegistryValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Siuf\\Rules", L"PeriodInNanoSeconds");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Siuf\\Rules", L"NumberOfSIUFInPeriod", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Siuf\\Rules", L"PeriodInNanoSeconds", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", L"DisableInventory", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", L"AITEnable", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Search", L"AllowSearchToUseLocation", 0);

    // ============================================================================
    // CONTENT DELIVERY / ADS / SUGGESTIONS
    // ============================================================================
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
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableWindowsConsumerFeatures", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent", L"DisableSoftLanding", 1);

    // ============================================================================
    // EXPLORER & UI BEHAVIOR
    // ============================================================================
    Log("[TWEAK] Applying Explorer & UI Behavior tweaks...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowSyncProviderNotifications", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"Hidden", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowSuperHidden", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"HideIcons", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"HideFileExt", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"NavPaneExpandToCurrentFolder", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"NavPaneShowAllFolders", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"SeparateProcess", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"DesktopProcess", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"LaunchTo", 1);
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences", L"%sysdrive%\\Windows\\explorer.exe", L"GpuPreference=2;");
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
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"DisablePreviewDesktop", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\DWM", L"EnableAeroPeek", 1);
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
    DeleteRegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{98D99750-0B8A-4c59-9151-589053683D73}");
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
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"ShowTaskViewButton", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People", L"PeopleBand", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"TaskbarGlomLevel", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"PeopleBand", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", L"TaskbarMn", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"HideSCAMeetNow", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"AutoEndTasks", 1);
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags");
    DeleteRegistryKey(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\AllFolders\\Shell", L"FolderType", L"NotSpecified");

    // ============================================================================
    // PERFORMANCE & MEMORY MANAGEMENT
    // ============================================================================
    Log("[TWEAK] Applying Performance & Memory Management tweaks...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"DisablePagingExecutive", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"LargeSystemCache", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnablePrefetcher", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnableSuperfetch", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"EnableBootTrace", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"SfTracingState", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"SwapfileControl", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"ClearPageFileAtShutdown", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"SystemResponsiveness", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"NetworkThrottlingIndex", 4294967295);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl", L"Win32PrioritySeparation", 22);

    // ============================================================================
    // NETWORK & TCP/IP
    // ============================================================================
    Log("[TWEAK] Applying Network & TCP/IP tweaks...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", L"DisabledComponents", 32);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"DefaultTTL", 100);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"IRPStackSize", 32);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SizReqBuf", 95268);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Psched", L"NonBestEffortLimit", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\parameters", L"AutoShareWks", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"AutoShareServer", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Ndu", L"Start", 4);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"IRPStackSize", 30);

    // ============================================================================
    // GRAPHICS & DWM
    // ============================================================================
    Log("[TWEAK] Applying Graphics & DWM settings...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", L"HwSchMode", 2);

    // ============================================================================
    // POWER & BOOT
    // ============================================================================
    Log("[TWEAK] Applying Power & Boot settings...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\BootControl", L"BootProgressAnimation", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Citrix", L"EnableVisualEffect", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\94d3a615-a899-4ac5-ae2b-e4d8f634367f", L"Attributes", 1);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", L"WaitToKillServiceTimeout", L"1000");

    // ============================================================================
    // SECURITY POLICIES
    // ============================================================================
    Log("[TWEAK] Applying Security Policies...");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"Negotiate", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential", 0);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions", L"MitigationOptions_FontBocking", L"1000000000000");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"PromptOnSecureDesktop", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", 5);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorEnhancedAdmin", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorUser", 3);

    // ============================================================================
    // SYSTEM TWEAKS (MISC)
    // ============================================================================
    Log("[TWEAK] Applying System Miscellaneous tweaks...");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"Max Cached Icons", L"8192");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme", 0);
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"Path", L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy", L"Unrestricted");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"Path", L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy", L"Unrestricted");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ContentIndex", L"FilterFilesWithUnknownExtensions", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\FileSystem", L"NtfsDisableLastAccessUpdate", 0);
    // PnPCapabilities for network adapters (0000-0030)
    for (int i = 0; i <= 30; i++) {
        wchar_t subkey[256];
        swprintf_s(subkey, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%04d", i);
        ConfigureRegistry(HKEY_LOCAL_MACHINE, subkey, L"PnPCapabilities", 24);
    }
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup", L"SourcePath", L"");
    ConfigureRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegDone", L"1");
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Command Processor", L"CompletionChar", 9);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\EnhancedStorageDevices", L"TCGSecurityActivationDisabled", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\NcdAutoSetup\\Private", L"AutoSetup", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableCdp", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main", L"AllowPrelaunch", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge", L"HideFirstRunExperience", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MiscPolicyInfo", L"ShippedWithReserves", 2);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PassedPolicy", L"ShippedWithReserves", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ReserveManager", L"ShippedWithReserves", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\common\\officeupdate", L"preventteamsinstall", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings", L"FlightSettingsMaxPauseDays", 730);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", L"BingSearchEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Search", L"BingSearchEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", L"NoTileApplicationNotification", 1);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", L"SensorPermissionState", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration", L"Status", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config", L"DODownloadMode", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization", L"DODownloadMode", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowFullControl", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\FileSystem", L"LongPathsEnabled", 1);
    ConfigureRegistry(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds", L"EnableFeeds", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Feeds", L"ShellFeedsTaskbarViewMode", 2);
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}");
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", L"System.IsPinnedToNameSpaceTree", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\DisableWindowsConsumerFeatures", L"", 1);

    // ============================================================================
    // UWP / BACKGROUND TASKS
    // ============================================================================
    Log("[TWEAK] Applying UWP & Background Tasks cleanup...");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy");
    DeleteRegistryKey(HKEY_CLASSES_ROOT, L"Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId\\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy");
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder", L"Attributes", 0x903a0004);
    ConfigureRegistry(HKEY_CLASSES_ROOT, L"Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\\ShellFolder", L"Attributes", 0x903a0004);

    // ============================================================================
    // GAME DVR & XBOX
    // ============================================================================
    Log("[TWEAK] Applying Game DVR & Xbox disabling...");
    ConfigureRegistry(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR", L"AppCaptureEnabled", 0);
    ConfigureRegistry(HKEY_CURRENT_USER, L"System\\GameConfigStore", L"GameDVR_Enabled", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", L"AllowGameDVR", 0);
    ConfigureRegistry(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR", L"value", 0);

    // ============================================================================
    // FILE ASSOCIATIONS (HTA)
    // ============================================================================
    Log("[TWEAK] Applying File Associations...");
    ConfigureRegistryString(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.hta\\OpenWithProgids", L"htafile", L"");

	// ============================================================================
	// WINDOWS SERVICES CONFIGURATION
	// ============================================================================
	Log("[TWEAK] Configuring Windows Services...");

	// --- Core telemetry / performance-related services ---
	SetServiceStartup(L"DiagTrack", SERVICE_DISABLED);
	SetServiceStartup(L"dmwappushservice", SERVICE_DISABLED);
	SetServiceStartup(L"SysMain", SERVICE_DISABLED);

	// --- Complete service configuration set ---
	SetServiceStartup(L"AxInstSV", SERVICE_DEMAND_START);
	SetServiceStartup(L"AarSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"ADPSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"AppReadiness", SERVICE_DEMAND_START);
	SetServiceStartup(L"AppIDSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"Appinfo", SERVICE_DEMAND_START);
	SetServiceStartup(L"ALG", SERVICE_DEMAND_START);
	SetServiceStartup(L"AppMgmt", SERVICE_DEMAND_START);
	SetServiceStartup(L"AssignedAccessManagerSvc", SERVICE_DISABLED);
	SetServiceStartup(L"tzautoupdate", SERVICE_DISABLED);
	SetServiceStartup(L"BthAvctpSvc", SERVICE_AUTO_START);
	SetServiceStartup(L"BrokerInfrastructure", SERVICE_AUTO_START);
	SetServiceStartup(L"BFE", SERVICE_AUTO_START);
	SetServiceStartup(L"BDESVC", SERVICE_DEMAND_START);
	SetServiceStartup(L"wbengine", SERVICE_DEMAND_START);
	SetServiceStartup(L"BTAGService", SERVICE_DEMAND_START);
	SetServiceStartup(L"bthserv", SERVICE_DEMAND_START);
	SetServiceStartup(L"BluetoothUserService_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"camsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"CaptureService_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"autotimesvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"CertPropSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"ClipSVC", SERVICE_DEMAND_START);
	SetServiceStartup(L"cbdhsvc_3a553", SERVICE_AUTO_START);
	SetServiceStartup(L"CloudBackupRestoreSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"KeyIso", SERVICE_AUTO_START);
	SetServiceStartup(L"EventSystem", SERVICE_AUTO_START);
	SetServiceStartup(L"COMSysApp", SERVICE_DEMAND_START);
	SetServiceStartup(L"CDPSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"CDPUserSvc_3a553", SERVICE_AUTO_START);
	SetServiceStartup(L"ConsentUxUserSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"PimIndexMaintenanceSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"CoreMessagingRegistrar", SERVICE_AUTO_START);
	SetServiceStartup(L"VaultSvc", SERVICE_AUTO_START);
	SetServiceStartup(L"CredentialEnrollmentManagerUserSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"CryptSvc", SERVICE_AUTO_START);
	SetServiceStartup(L"DsSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DusmSvc", SERVICE_AUTO_START);
	SetServiceStartup(L"DcomLaunch", SERVICE_AUTO_START);
	SetServiceStartup(L"dcsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DoSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DeviceAssociationService", SERVICE_DEMAND_START);
	SetServiceStartup(L"DeviceInstall", SERVICE_DEMAND_START);
	SetServiceStartup(L"DmEnrollmentSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DsmSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DeviceAssociationBrokerSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"DevicePickerUserSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"DevicesFlowUserSvc_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"DevQueryBroker", SERVICE_DEMAND_START);
	SetServiceStartup(L"Dhcp", SERVICE_AUTO_START);
	SetServiceStartup(L"diagsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"DPS", SERVICE_AUTO_START);
	SetServiceStartup(L"WdiServiceHost", SERVICE_DEMAND_START);
	SetServiceStartup(L"WdiSystemHost", SERVICE_DEMAND_START);
	SetServiceStartup(L"DisplayEnhancementService", SERVICE_DEMAND_START);
	SetServiceStartup(L"DispBrokerDesktopSvc", SERVICE_AUTO_START);
	SetServiceStartup(L"TrkWks", SERVICE_AUTO_START);
	SetServiceStartup(L"MSDTC", SERVICE_DEMAND_START);
	SetServiceStartup(L"Dnscache", SERVICE_AUTO_START);
	SetServiceStartup(L"MapsBroker", SERVICE_AUTO_START);
	SetServiceStartup(L"embeddedmode", SERVICE_DEMAND_START);
	SetServiceStartup(L"EFS", SERVICE_DEMAND_START);
	SetServiceStartup(L"EntAppSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"EapHost", SERVICE_DEMAND_START);
	SetServiceStartup(L"fhsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"fdPHost", SERVICE_DEMAND_START);
	SetServiceStartup(L"FDResPub", SERVICE_DEMAND_START);
	SetServiceStartup(L"GameInputSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"lfsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"GraphicsPerfSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"gpsvc", SERVICE_AUTO_START);
	SetServiceStartup(L"hidserv", SERVICE_DEMAND_START);
	SetServiceStartup(L"HvHost", SERVICE_DEMAND_START);
	SetServiceStartup(L"IKEEXT", SERVICE_DEMAND_START);
	SetServiceStartup(L"SharedAccess", SERVICE_DEMAND_START);
	SetServiceStartup(L"InventorySvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"iphlpsvc", SERVICE_DISABLED);
	SetServiceStartup(L"PolicyAgent", SERVICE_DEMAND_START);
	SetServiceStartup(L"KtmRm", SERVICE_DEMAND_START);
	SetServiceStartup(L"lltdsvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"wlpasvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"MessagingService_3a553", SERVICE_DEMAND_START);
	SetServiceStartup(L"NetTcpPortSharing", SERVICE_DISABLED);
	SetServiceStartup(L"Netlogon", SERVICE_AUTO_START);
	SetServiceStartup(L"NlaSvc", SERVICE_DEMAND_START);
	SetServiceStartup(L"nsi", SERVICE_AUTO_START);
	SetServiceStartup(L"ssh-agent", SERVICE_DISABLED);
	SetServiceStartup(L"Spooler", SERVICE_DISABLED);
	SetServiceStartup(L"RemoteRegistry", SERVICE_DISABLED);
	SetServiceStartup(L"WerSvc", SERVICE_DISABLED);
	SetServiceStartup(L"XboxGipSvc", SERVICE_DISABLED);
	SetServiceStartup(L"wscsvc", SERVICE_DISABLED);
	SetServiceStartup(L"AJRouter", SERVICE_DISABLED);
	SetServiceStartup(L"Fax", SERVICE_DISABLED);
	SetServiceStartup(L"RemoteAccess", SERVICE_DISABLED);
	SetServiceStartup(L"UevAgentService", SERVICE_DISABLED);
	SetServiceStartup(L"XblAuthManager", SERVICE_DISABLED);
	SetServiceStartup(L"XblGameSave", SERVICE_DISABLED);
	SetServiceStartup(L"XboxNetApiSvc", SERVICE_DISABLED);
	SetServiceStartup(L"uhssvc", SERVICE_DISABLED);
	SetServiceStartup(L"superfetch", SERVICE_DISABLED);

	// --- Pattern-based per-user service handling ---
	const wchar_t* userServicePatterns[] = {
		L"BluetoothUserService_",
		L"BcastDVRUserService_",
		L"CDPUserSvc_",
		L"CaptureService_",
		L"ConsentUxUserSvc_",
		L"CredentialEnrollmentManagerUserSvc_",
		L"DeviceAssociationBrokerSvc_",
		L"DevicePickerUserSvc_",
		L"DevicesFlowUserSvc_",
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
		DWORD startupType = SERVICE_DEMAND_START;

		if (wcscmp(pattern, L"CDPUserSvc_") == 0 ||
			wcscmp(pattern, L"OneSyncSvc_") == 0 ||
			wcscmp(pattern, L"webthreatdefusersvc_") == 0) {
			startupType = SERVICE_AUTO_START;
		}

		EnumerateAndConfigureUserServices(pattern, startupType);
	}

	Log("[TWEAK] System optimizations applied successfully.");
    Log("*********************************");
}