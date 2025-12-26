#include "tweaks.h"
#include "globals.h"
#include "constants.h"
#include "logger.h"
#include "utils.h"
#include "sysinfo.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

// NT MEMORY TRIM DEFINITIONS
typedef NTSTATUS (NTAPI *NtSetSystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

static NtSetSystemInformation_t pNtSetSystemInformation = nullptr;

static bool InitNtMemoryApi()
{
    if (pNtSetSystemInformation)
        return true;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    pNtSetSystemInformation =
        reinterpret_cast<NtSetSystemInformation_t>(
            GetProcAddress(ntdll, "NtSetSystemInformation")
        );

    return pNtSetSystemInformation != nullptr;
}

void IntelligentRamClean()
{
    // CRITICAL FIX: Prevent 0x1A BSOD during Hibernate/Sleep
    if (g_isSuspended.load()) return;

    if (!InitNtMemoryApi())
        return;

    SYSTEM_MEMORY_LIST_COMMAND cmd = MemoryPurgeStandbyList;

    NTSTATUS st = pNtSetSystemInformation(
        SystemMemoryListInformation,
        &cmd,
        sizeof(cmd)
    );

    if (NT_SUCCESS(st))
    {
        Log("[RAM] Standby list purged successfully");
    }
    else
    {
        Log("[RAM] NtSetSystemInformation failed: 0x" +
            std::to_string(static_cast<unsigned>(st)));
    }
}

static bool VerifyPrioritySeparation(DWORD expectedVal)
{
    DWORD currentVal = GetCurrentPrioritySeparation();
    
    if (currentVal == 0xFFFFFFFF)
    {
        Log("Verification failed: Unable to read registry");
        g_cachedRegistryValue.store(0xFFFFFFFF);
        return false;
    }
    
    if (currentVal == expectedVal)
    {
        Log("√ Verification SUCCESS: " + GetModeDescription(currentVal));
        return true;
    }
    else
    {
        Log("× Verification MISMATCH: Expected 0x" + std::to_string(expectedVal) + 
            " but got 0x" + std::to_string(currentVal));
        return false;
    }
}

bool SetPrioritySeparation(DWORD val)
{
    // Registry Write Guard
    DWORD cachedVal = g_cachedRegistryValue.load();
    if (cachedVal != 0xFFFFFFFF && cachedVal == val)
    {
        Log("Registry Write Guard: Skipping redundant write for value 0x" + 
            std::to_string(val) + " (already cached)");
        return true;
    }
    
    HKEY rawKey = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                            0, KEY_SET_VALUE, &rawKey);
    
    // RAII wrapper takes ownership immediately
    UniqueRegKey key(rawKey);

    if (rc != ERROR_SUCCESS) 
    {
        if (rc == ERROR_ACCESS_DENIED)
            Log("Registry access denied - need admin rights");
        else
            Log("Registry open failed: " + std::to_string(rc));
        return false;
    }
    
    rc = RegSetValueExW(key.get(), L"Win32PrioritySeparation", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&val), sizeof(val));
    // No explicit RegCloseKey needed - automatic cleanup
    
    if (rc == ERROR_SUCCESS)
    {
        g_cachedRegistryValue.store(val);
        Sleep(50);
        VerifyPrioritySeparation(val);
        return true;
    }
    else
    {
        Log("Registry set failed: " + std::to_string(rc));
        return false;
    }
}

void SetHybridCoreAffinity(DWORD pid, int mode)
{
    if (!g_caps.hasHybridCores && !g_caps.supportsPowerThrottling)
        return;
    
    UniqueHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 
                                      FALSE, pid));
    if (!hProcess)
        return;
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
        return; // hProcess auto-closes here
    
    bool success = false;
    
    // Method 1: CPU Set Pinning
    if (g_caps.hasHybridCores)
    {
        typedef BOOL (WINAPI *SetProcessDefaultCpuSetsPtr)(HANDLE, CONST ULONG*, ULONG);
        auto pSetProcessDefaultCpuSets = 
            reinterpret_cast<SetProcessDefaultCpuSetsPtr>(
                GetProcAddress(kernel32, "SetProcessDefaultCpuSets"));
        
        if (pSetProcessDefaultCpuSets)
        {
            std::lock_guard lock(g_cpuSetMtx);
            if (mode == 1 && !g_pCoreSets.empty()) 
            {
                if (pSetProcessDefaultCpuSets(hProcess.get(), g_pCoreSets.data(), 
                                              static_cast<ULONG>(g_pCoreSets.size())))
                {
                    Log("[HYBRID] CPU Set Pinning: Process pinned to " + 
                        std::to_string(g_pCoreSets.size()) + " P-cores (performance)");
                    success = true;
                }
            }
            else if (mode == 2 && !g_eCoreSets.empty()) 
            {
                if (pSetProcessDefaultCpuSets(hProcess.get(), g_eCoreSets.data(), 
                                              static_cast<ULONG>(g_eCoreSets.size())))
                {
                    Log("[HYBRID] CPU Set Pinning: Process pinned to " + 
                        std::to_string(g_eCoreSets.size()) + " E-cores (efficiency)");
                    success = true;
                }
            }
        }
    }
    
    // Method 2: Power Throttling API
    if (!success && g_caps.supportsPowerThrottling)
    {
        typedef BOOL (WINAPI *SetProcessInformationPtr)(
            HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
        
        auto pSetProcessInformation = 
            reinterpret_cast<SetProcessInformationPtr>(
                GetProcAddress(kernel32, "SetProcessInformation"));
        
        if (pSetProcessInformation)
        {
            PROCESS_POWER_THROTTLING_STATE throttlingState = { 0 };
            throttlingState.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
            throttlingState.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
            
            if (mode == 1) throttlingState.StateMask = 0;
            else throttlingState.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
            
            if (pSetProcessInformation(hProcess.get(), ProcessPowerThrottling, 
                                      &throttlingState, sizeof(throttlingState)))
            {
                Log("[HYBRID] Power Throttling: " + 
                    std::string(mode == 1 ? "DISABLED (performance)" : "ENABLED (eco mode)"));
            }
        }
    }
}

void SetAmd3DVCacheAffinity(DWORD pid, int mode)
{
    if (!g_cpuInfo.hasAmd3DVCache) return;
    if (g_cpuInfo.ccd0CoreSets.empty()) return;
    
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 
                                   FALSE, pid);
    if (!hProcess) return;
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
    {
        CloseHandle(hProcess);
        return;
    }
    
    typedef BOOL (WINAPI *SetProcessDefaultCpuSetsPtr)(HANDLE, CONST ULONG*, ULONG);
    auto pSetProcessDefaultCpuSets = 
        reinterpret_cast<SetProcessDefaultCpuSetsPtr>(
            GetProcAddress(kernel32, "SetProcessDefaultCpuSets"));
    
    if (!pSetProcessDefaultCpuSets)
    {
        CloseHandle(hProcess);
        return;
    }
    
    if (mode == 1) // GAME MODE
    {
        if (pSetProcessDefaultCpuSets(hProcess, g_cpuInfo.ccd0CoreSets.data(), 
                                      static_cast<ULONG>(g_cpuInfo.ccd0CoreSets.size())))
        {
            Log("[AMD-3D] Game pinned to CCD0 (" + 
                std::to_string(g_cpuInfo.ccd0CoreSets.size()) + 
                " cores with 3D V-Cache = 96MB L3)");
        }
        else
        {
            DWORD err = GetLastError();
            Log("[AMD-3D] Failed to pin to CCD0: " + std::to_string(err));
        }
    }
    else if (mode == 2) // BROWSER MODE
    {
        std::vector<ULONG> allCores;
        allCores.insert(allCores.end(), g_cpuInfo.ccd0CoreSets.begin(), g_cpuInfo.ccd0CoreSets.end());
        allCores.insert(allCores.end(), g_cpuInfo.ccd1CoreSets.begin(), g_cpuInfo.ccd1CoreSets.end());
        
        if (pSetProcessDefaultCpuSets(hProcess, allCores.data(), 
                                      static_cast<ULONG>(allCores.size())))
        {
            Log("[AMD-3D] Browser using all " + std::to_string(allCores.size()) + 
                " cores (CCD0 + CCD1+ for multitasking)");
        }
    }
    
    CloseHandle(hProcess);
}

static bool IsIoPriorityBlockedBySystem()
{
    if (!g_caps.hasAdminRights) return true;
    
    HANDLE hCurrent = GetCurrentProcess();
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return true;
    
    typedef NTSTATUS (NTAPI *NtSetInformationProcessPtr)(
        HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
    
    auto pNtSetInformationProcess = 
        reinterpret_cast<NtSetInformationProcessPtr>(
            GetProcAddress(ntdll, "NtSetInformationProcess"));
    
    if (!pNtSetInformationProcess) return true;
    
    ULONG priorities[] = {IoPriorityHigh, IoPriorityNormal, IoPriorityLow};
    bool anySuccess = false;
    
    for (ULONG priority : priorities)
    {
        NTSTATUS status = pNtSetInformationProcess(
            hCurrent, ProcessIoPriority, &priority, sizeof(priority));
        
        if (NT_SUCCESS(status))
        {
            anySuccess = true;
            break;
        }
    }
    
    return !anySuccess;
}

void SetProcessIoPriority(DWORD pid, int mode)
{
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 
                                   FALSE, pid);
    if (!hProcess)
    {
        Log("[I/O] Failed to open process " + std::to_string(pid) + ": " + std::to_string(GetLastError()));
        return;
    }
    
    bool ioPrioritySet = false;
    
    // Method 1: Try NtSetInformationProcess (most compatible)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        typedef NTSTATUS (NTAPI *NtSetInformationProcessPtr)(
            HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
        
        auto pNtSetInformationProcess = 
            reinterpret_cast<NtSetInformationProcessPtr>(
                GetProcAddress(ntdll, "NtSetInformationProcess"));
        
        if (pNtSetInformationProcess)
        {
            ULONG ioPriority;
            if (mode == 1) 
            {
                ioPriority = IoPriorityHigh;
            }
            else 
            {
                ioPriority = IoPriorityLow;
            }
            
            NTSTATUS status = pNtSetInformationProcess(
                hProcess,
                ProcessIoPriority,
                &ioPriority,
                sizeof(ioPriority)
            );
            
            if (NT_SUCCESS(status))
            {
                Log("[I/O] Priority set: " + 
                    std::string(mode == 1 ? "HIGH (game)" : "LOW (browser)") + " using NtSetInformationProcess");
                ioPrioritySet = true;
            }
            else if (status == 0xC00000C9 && mode == 1)
            {
                ioPriority = IoPriorityNormal;
                status = pNtSetInformationProcess(
                    hProcess,
                    ProcessIoPriority,
                    &ioPriority,
                    sizeof(ioPriority)
                );
                
                if (NT_SUCCESS(status))
                {
                    Log("[I/O] High priority unavailable, fallback: NORMAL (game) using NtSetInformationProcess");
                    ioPrioritySet = true;
                }
            }
        }
    }
    
	if (!ioPrioritySet)
	{
		if (IsIoPriorityBlockedBySystem())
		{
			Log("[I/O] I/O priority APIs blocked by system - using enhanced thread priority fallback");
		}
		else
		{
			Log("[I/O] I/O priority setting failed - using enhanced fallback strategy");
		}

        // Method 2: Thread Priority
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te32 = {0};
            te32.dwSize = sizeof(THREADENTRY32);
            
            if (Thread32First(hThreadSnap, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == pid)
                    {
                        HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread)
                        {
                            int threadPriority = (mode == 1) ? THREAD_PRIORITY_HIGHEST : THREAD_PRIORITY_LOWEST;
                            if (SetThreadPriority(hThread, threadPriority))
                            {
                                ioPrioritySet = true;
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te32));
            }
            CloseHandle(hThreadSnap);
            
            if (ioPrioritySet)
            {
                Log("[I/O] Thread priority set: " + 
                    std::string(mode == 1 ? "HIGHEST (game)" : "LOWEST (browser)") + " for process threads");
            }
        }
        
        // Method 3: Process Priority Class
        if (!ioPrioritySet)
        {
            DWORD priorityClass = (mode == 1) ? HIGH_PRIORITY_CLASS : IDLE_PRIORITY_CLASS;
            if (SetPriorityClass(hProcess, priorityClass))
            {
                Log("[I/O] Process priority set: " + 
                    std::string(mode == 1 ? "HIGH (game)" : "IDLE (browser)") + " using SetPriorityClass");
            }
            else
            {
                priorityClass = (mode == 1) ? ABOVE_NORMAL_PRIORITY_CLASS : BELOW_NORMAL_PRIORITY_CLASS;
                if (SetPriorityClass(hProcess, priorityClass))
                {
                    Log("[I/O] Fallback priority set: " + 
                        std::string(mode == 1 ? "ABOVE_NORMAL (game)" : "BELOW_NORMAL (browser)") + " using SetPriorityClass");
                }
            }
        }
    }
    
    CloseHandle(hProcess);
}

void SetNetworkQoS(int mode)
{
    if (!g_caps.hasAdminRights) return;
    
    static std::atomic<DWORD> g_cachedNetworkQoS{0xFFFFFFFF};
    
    DWORD targetValue = (mode == 1) ? 0xFFFFFFFF : 10;
    
    DWORD cached = g_cachedNetworkQoS.load();
    if (cached != 0xFFFFFFFF && cached == targetValue)
    {
        return;
    }
    
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key);
    
    if (rc != ERROR_SUCCESS)
    {
        Log("[QoS] Failed to open registry key: " + std::to_string(rc));
        return;
    }
    
    DWORD currentValue = 0;
    DWORD size = sizeof(currentValue);
    if (RegQueryValueExW(key, L"NetworkThrottlingIndex", nullptr, nullptr,
                        reinterpret_cast<BYTE*>(&currentValue), &size) == ERROR_SUCCESS)
    {
        if (currentValue == targetValue)
        {
            g_cachedNetworkQoS.store(targetValue);
            RegCloseKey(key);
            return;
        }
    }
    
    rc = RegSetValueExW(key, L"NetworkThrottlingIndex", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&targetValue), sizeof(targetValue));
    
    if (rc == ERROR_SUCCESS)
    {
        g_cachedNetworkQoS.store(targetValue);
        Log("[QoS] Network throttling " + 
            std::string(mode == 1 ? "DISABLED (game mode)" : "ENABLED (browser mode)"));
    }
    
    RegCloseKey(key);
}

void SetMemoryCompression(int mode)
{
    if (!g_caps.hasAdminRights) return;
    if (!g_caps.isWindows10OrNewer) return;
    
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return;
    
    uint64_t totalGB = ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL);
    
    bool shouldCompress = false;
    std::string reason;
    
	// Changed minimum from 7GB (8GB stick) to 3GB (4GB stick) to support lower-end devices
    if (totalGB < 3)
    {
        reason = "System has " + std::to_string(totalGB) + "GB RAM - skipping (critical low memory)";
        Log("[MEMORY] " + reason);
        return;
    }
	// Fix: Adjusted range to cover the new minimum (3GB+)
    // Compression is useful for anything under 32GB in modern gaming scenarios
    else if (totalGB >= 3 && totalGB <= 32)
    {
        shouldCompress = (mode == 1); 
        reason = "System has " + std::to_string(totalGB) + "GB RAM - compression beneficial";
    }
    else
    {
        // For >32GB, compression is rarely needed, but we won't force disable it if the user wants it.
        // We just won't actively manage it.
        shouldCompress = false;
        reason = "System has " + std::to_string(totalGB) + "GB RAM - compression unnecessary (high capacity)";
        Log("[MEMORY] " + reason);
        return;
    }
    
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key);
    
    if (rc != ERROR_SUCCESS)
    {
        Log("[MEMORY] Failed to open registry key: " + std::to_string(rc));
        return;
    }
    
    if (g_originalMemoryCompression.load() == 0xFFFFFFFF)
    {
        DWORD original = 0;
        DWORD size = sizeof(original);
        if (RegQueryValueExW(key, L"DisablePagingExecutive", nullptr, nullptr,
                            reinterpret_cast<BYTE*>(&original), &size) == ERROR_SUCCESS)
        {
            g_originalMemoryCompression.store(original);
            Log("[MEMORY] Saved original compression state: " + std::to_string(original));
        }
    }
    
    DWORD targetValue;
    
    if (mode == 1 && shouldCompress)
    {
        targetValue = 1;
    }
    else if (mode == 2 && g_memoryCompressionModified.load())
    {
        DWORD original = g_originalMemoryCompression.load();
        if (original == 0xFFFFFFFF)
        {
            RegCloseKey(key);
            return;
        }
        targetValue = original;
    }
    else
    {
        RegCloseKey(key);
        return;
    }
    
	DWORD currentValue = 0;
    DWORD size = sizeof(currentValue);
    if (RegQueryValueExW(key, L"DisablePagingExecutive", nullptr, nullptr,
                        reinterpret_cast<BYTE*>(&currentValue), &size) == ERROR_SUCCESS)
    {
        // Fix: Validate size to prevent partial reads or buffer overflow risks
        if (size == sizeof(currentValue) && currentValue == targetValue)
        {
            RegCloseKey(key);
            return; 
        }
    }
    
    rc = RegSetValueExW(key, L"DisablePagingExecutive", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&targetValue), sizeof(targetValue));
    
    if (rc == ERROR_SUCCESS)
    {
        if (mode == 1)
        {
            g_memoryCompressionModified.store(true);
            Log("[MEMORY] Compression ENABLED (reduces paging for games) - " + reason);
        }
        else
        {
            g_memoryCompressionModified.store(false);
            Log("[MEMORY] Compression RESTORED to original state");
        }
    }
    
    RegCloseKey(key);
}

void SetGpuPriority(DWORD pid, int mode)
{
    if (!g_gpuSchedulingAvailable.load()) return;
    
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 
                                   FALSE, pid);
    if (!hProcess) return;
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        typedef NTSTATUS (NTAPI *NtSetInformationProcessPtr)(
            HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
        
        auto pNtSetInformationProcess = 
            reinterpret_cast<NtSetInformationProcessPtr>(
                GetProcAddress(ntdll, "NtSetInformationProcess"));
		if (pNtSetInformationProcess)
        {
            PROCESS_INFORMATION_CLASS gpuPriorityClass = 
                static_cast<PROCESS_INFORMATION_CLASS>(UndocumentedApi::ProcessGpuPriority);
            
            ULONG gpuPriority = (mode == 1) ? 1 : 0;
            
            NTSTATUS status = pNtSetInformationProcess(
                hProcess, gpuPriorityClass, &gpuPriority, sizeof(gpuPriority));
            
            if (NT_SUCCESS(status))
            {
                Log("[GPU] Priority set: " + 
                    std::string(mode == 1 ? "HIGH (game)" : "NORMAL (browser)"));
            }
        }
    }
    
    CloseHandle(hProcess);
}

void SetTimerResolution(int mode)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    
    typedef NTSTATUS (NTAPI *NtSetTimerResolutionPtr)(ULONG, BOOLEAN, PULONG);
    typedef NTSTATUS (NTAPI *NtQueryTimerResolutionPtr)(PULONG, PULONG, PULONG);
    
    auto pNtSetTimerResolution = 
        reinterpret_cast<NtSetTimerResolutionPtr>(
            GetProcAddress(ntdll, "NtSetTimerResolution"));
    
	auto pNtQueryTimerResolution = 
        reinterpret_cast<NtQueryTimerResolutionPtr>(
            GetProcAddress(ntdll, "NtQueryTimerResolution"));
    
    if (!pNtSetTimerResolution || !pNtQueryTimerResolution) return;

    // Fix: Capture original resolution once
    if (g_originalTimerResolution.load() == 0)
    {
        ULONG min = 0, max = 0, current = 0;
        if (NT_SUCCESS(pNtQueryTimerResolution(&min, &max, &current)))
        {
            g_originalTimerResolution.store(current);
        }
    }
    
    if (mode == 1)
    {
        ULONG desired = 5000;
        ULONG actual = 0;
        
        NTSTATUS status = pNtSetTimerResolution(desired, TRUE, &actual);
        if (NT_SUCCESS(status))
        {
            g_timerResolutionActive.store(actual);
            Log("[TIMER] Game mode: " + std::to_string(actual / 10000.0) + 
                "ms precision (reduces input lag)");
        }
    }
	else if (mode == 2 && g_timerResolutionActive.load() != 0)
    {
        ULONG min, max, current;
        if (NT_SUCCESS(pNtQueryTimerResolution(&min, &max, &current)))
        {
            ULONG actual = 0;
            // Fix Restore original resolution or disable request properly
            ULONG restoreVal = g_originalTimerResolution.load();
            if (restoreVal == 0) restoreVal = current; // Fallback
            
            pNtSetTimerResolution(restoreVal, FALSE, &actual);
            g_timerResolutionActive.store(0);
            Log("[TIMER] Browser mode: Released timer request (system default)");
        }
    }
}

void SetProcessAffinity(DWORD pid, int mode)
{
    if (g_physicalCoreCount == 0) return;
	if (g_isLowCoreCount) return; // Fix Skip affinity on single-core systems
    
	// Fix Better error handling/recovery
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 
                                   FALSE, pid);
if (!hProcess) 
    {
        DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED)
        {
            Log("[AFFINITY] OpenProcess failed for PID " + std::to_string(pid) + ": " + std::to_string(err));
        }
#ifdef _DEBUG
        else
        {
            Log("[DEBUG] [AFFINITY] OpenProcess Access Denied for PID " + std::to_string(pid));
        }
#endif
        return;
    }
    
    DWORD_PTR affinityMask = 0;
    
    if (mode == 1)
    {
        affinityMask = g_physicalCoreMask;
        
        if (SetProcessAffinityMask(hProcess, affinityMask))
        {
            Log("[AFFINITY] Game pinned to " + std::to_string(g_physicalCoreCount) + 
                " physical cores (HT disabled for game)");
        }
    }
	else if (mode == 2)
    {
        // Fix Safe affinity mask calculation for 64+ cores or error states
        if (g_logicalCoreCount > 0 && g_logicalCoreCount < 64)
            affinityMask = (1ULL << g_logicalCoreCount) - 1;
        else
            affinityMask = (DWORD_PTR)-1; // Use all available cores

        if (SetProcessAffinityMask(hProcess, affinityMask))
        {
            Log("[AFFINITY] Browser using all " + std::to_string(g_logicalCoreCount) + 
                " logical cores (HT enabled)");
        }
    }
    
    CloseHandle(hProcess);
}

// Helper: Trim background browsers
static void TrimBrowserWorkingSet(DWORD pid)
{
    // Check trim throttle
    bool shouldTrim = false;
    {
        std::lock_guard lock(g_trimTimeMtx);
        auto now = std::chrono::steady_clock::now();
        auto it = g_lastTrimTimes.find(pid);
        
        if (it == g_lastTrimTimes.end())
        {
            shouldTrim = true;
            g_lastTrimTimes[pid] = now;
        }
        else
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second).count();
            
            if (elapsed >= 60)
            {
                shouldTrim = true;
                it->second = now;
            }
        }
    }
    
    if (!shouldTrim) return;
    
    HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA, FALSE, pid);
    if (hProcess)
    {
        if (SetProcessWorkingSetSize(hProcess, static_cast<SIZE_T>(-1), static_cast<SIZE_T>(-1)))
        {
            Log("[WORKSET] Background browser PID " + std::to_string(pid) + " trimmed");
        }
        CloseHandle(hProcess);
    }
}

void SetWorkingSetLimits(DWORD pid, int mode)
{
    if (!g_workingSetManagementAvailable.load()) return;
	if (g_isLowMemory) return; // Fix Skip working set limits on low RAM systems
    
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return;
    
    uint64_t totalGB = ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL);
    uint64_t availMB = ms.ullAvailPhys >> 20;
    
	// Expanded range: Allow 4GB+ (min 3) and remove 16GB upper limit
    if (totalGB < 3)
    {
        static bool loggedOnce = false;
        if (!loggedOnce)
        {
            Log("[WORKSET] System has " + std::to_string(totalGB) + 
                "GB RAM - working set optimization skipped (requires 4GB+)");
            loggedOnce = true;
        }
        return;
    }
    
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, 
        FALSE, pid);
    
    if (!hProcess)
    {
        DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED)
        {
            Log("[WORKSET] Failed to open process " + std::to_string(pid) + 
                ": " + std::to_string(err));
        }
        return;
    }
    
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
    {
        CloseHandle(hProcess);
        return;
    }
    
    typedef BOOL (WINAPI *SetProcessWorkingSetSizeExPtr)(HANDLE, SIZE_T, SIZE_T, DWORD);
    typedef BOOL (WINAPI *GetProcessWorkingSetSizeExPtr)(HANDLE, PSIZE_T, PSIZE_T, PDWORD);
    
    auto pSetProcessWorkingSetSizeEx = 
        reinterpret_cast<SetProcessWorkingSetSizeExPtr>(
            GetProcAddress(kernel32, "SetProcessWorkingSetSizeEx"));
    
    auto pGetProcessWorkingSetSizeEx = 
        reinterpret_cast<GetProcessWorkingSetSizeExPtr>(
            GetProcAddress(kernel32, "GetProcessWorkingSetSizeEx"));
    
    if (!pSetProcessWorkingSetSizeEx)
    {
        CloseHandle(hProcess);
        return;
    }
    
    if (mode == 1) // GAME MODE
    {
        if (pGetProcessWorkingSetSizeEx)
        {
            SIZE_T minWS = 0, maxWS = 0;
            DWORD flags = 0;
            
            if (pGetProcessWorkingSetSizeEx(hProcess, &minWS, &maxWS, &flags))
            {
                std::lock_guard lock(g_workingSetMtx);
                g_originalWorkingSets[pid] = maxWS;
            }
        }
        
        SIZE_T minWS = 50ULL * 1024 * 1024;
        SIZE_T maxWS = static_cast<SIZE_T>(-1);
        
        if (availMB < 3072)
        {
            maxWS = 2048ULL * 1024 * 1024;
        }
        else if (availMB < 5120)
        {
            maxWS = 4096ULL * 1024 * 1024;
        }
        
        DWORD flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
        
        if (pSetProcessWorkingSetSizeEx(hProcess, minWS, maxWS, flags))
        {
            Log("[WORKSET] Game working set expanded: min=" + 
                std::to_string(minWS / 1024 / 1024) + "MB, max=" + 
                (maxWS == static_cast<SIZE_T>(-1) ? 
                    std::string("UNLIMITED") : 
                    std::to_string(maxWS / 1024 / 1024) + "MB") +
                " (prevents paging)");
        }
        
        CloseHandle(hProcess);
        
		// Trim browsers
        std::shared_lock lg(g_setMtx);
        std::unordered_set<std::wstring> browsersCopy = g_browsers;
        lg.unlock();
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            
            if (Process32FirstW(hSnapshot, &pe))
            {
                do
                {
                    std::wstring exeName = pe.szExeFile;
                    asciiLower(exeName);
                    
                    if (browsersCopy.count(exeName) && pe.th32ProcessID != pid)
                    {
                        TrimBrowserWorkingSet(pe.th32ProcessID);
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return;
    }
    else if (mode == 2) // BROWSER MODE
    {
        SIZE_T originalMax = 0;
        {
            std::lock_guard lock(g_workingSetMtx);
            auto it = g_originalWorkingSets.find(pid);
            if (it != g_originalWorkingSets.end())
            {
                originalMax = it->second;
                g_originalWorkingSets.erase(it);
            }
        }
        
        if (pSetProcessWorkingSetSizeEx && originalMax > 0)
        {
            SIZE_T minWS = 10 * 1024 * 1024;
            SIZE_T maxWS = originalMax;
            DWORD flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
            
            if (pSetProcessWorkingSetSizeEx(hProcess, minWS, maxWS, flags))
            {
                Log("[WORKSET] Browser working set restored to original limits");
            }
        }
    }
    
    CloseHandle(hProcess);
}

void SetPriorityBoostControl(DWORD pid, int mode)
{
    if (!g_dpcLatencyAvailable.load()) return;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 
                                   FALSE, pid);
    if (!hProcess) return;
    
    if (mode == 1) // GAME MODE
    {
        if (SetProcessPriorityBoost(hProcess, TRUE)) 
        {
            std::lock_guard lock(g_dpcStateMtx);
            g_processesWithBoostDisabled[pid] = true;
            Log("[DPC] Priority boost DISABLED for game (eliminates microstutter)");
        }
        else
        {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED)
            {
                Log("[DPC] Failed to disable priority boost: " + std::to_string(err));
            }
        }
    }
    else if (mode == 2) // BROWSER MODE
    {
        bool wasDisabled = false;
        {
            std::lock_guard lock(g_dpcStateMtx);
            auto it = g_processesWithBoostDisabled.find(pid);
            if (it != g_processesWithBoostDisabled.end())
            {
                wasDisabled = true;
                g_processesWithBoostDisabled.erase(it);
            }
        }
        
        if (wasDisabled)
        {
            if (SetProcessPriorityBoost(hProcess, FALSE)) 
            {
                Log("[DPC] Priority boost RESTORED for browser");
            }
        }
    }
    
    CloseHandle(hProcess);
}

void OptimizeThreadScheduling(DWORD pid, int mode)
{
    if (!g_dpcLatencyAvailable.load()) return;
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    
    typedef NTSTATUS (NTAPI *NtSetInformationThreadPtr)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
    auto pNtSetInformationThread = 
        reinterpret_cast<NtSetInformationThreadPtr>(
            GetProcAddress(ntdll, "NtSetInformationThread"));
    
    if (!pNtSetInformationThread) return;
    
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    
    THREADENTRY32 te32{};
    te32.dwSize = sizeof(te32);
    
    int threadsOptimized = 0;
    int threadsSkipped = 0;
    
    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(
                    THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, 
                    FALSE, te32.th32ThreadID);
                
                if (hThread)
                {
					if (mode == 1) // GAME MODE
                    {
                        LONG basePriority = THREAD_PRIORITY_HIGHEST;
                        NTSTATUS status = pNtSetInformationThread(
                            hThread, 
                            static_cast<THREADINFOCLASS>(UndocumentedApi::ThreadBasePriority), 
                            &basePriority, 
                            sizeof(basePriority));
                        
                        if (NT_SUCCESS(status))
                        {
                            BOOL disableBoost = TRUE;
                            if (SetThreadPriorityBoost(hThread, disableBoost))
                            {
                                threadsOptimized++;
                            }
                            else
                            {
                                threadsOptimized++;
                            }
                        }
                        else
                        {
                            threadsSkipped++;
                        }
                    }
                    else if (mode == 2) // BROWSER MODE
                    {
						LONG basePriority = THREAD_PRIORITY_NORMAL;
                        pNtSetInformationThread(
                            hThread, 
                            static_cast<THREADINFOCLASS>(UndocumentedApi::ThreadBasePriority), 
                            &basePriority, 
                            sizeof(basePriority));
                        
                        BOOL disableBoost = FALSE;
                        SetThreadPriorityBoost(hThread, disableBoost);
                    }
                    
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    
    CloseHandle(hThreadSnap);
    
    if (threadsOptimized > 0)
    {
        std::string logMsg = "[THREAD] Optimized " + std::to_string(threadsOptimized) + 
            " game threads (THREAD_PRIORITY_HIGHEST + boost disabled)";
        
        if (threadsSkipped > 0)
        {
            logMsg += " [" + std::to_string(threadsSkipped) + " skipped - access denied]";
        }
        
        Log(logMsg);
    }
    else if (mode == 1)
    {
        Log("[THREAD] Warning: Could not optimize any threads (may lack permissions)");
    }
}

void SetTimerCoalescingControl(int mode)
{
    if (!g_timerCoalescingAvailable.load()) return;
    if (!g_caps.hasAdminRights) return;
    
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key);
    
    if (rc != ERROR_SUCCESS)
    {
        rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
            0, nullptr, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr);
        
        if (rc != ERROR_SUCCESS)
        {
            Log("[DPC] Failed to open/create timer coalescing key: " + std::to_string(rc));
            return;
        }
    }
    
    if (mode == 1) // GAME MODE
    {
        DWORD disableValue = 1;
        rc = RegSetValueExW(key, L"CoalescingTimerInterval", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&disableValue), sizeof(disableValue));
        
        if (rc == ERROR_SUCCESS)
        {
            g_highResTimersActive.store(true);
            Log("[DPC] Timer coalescing DISABLED (precise interrupt timing for games)");
        }
        else
        {
            Log("[DPC] Failed to disable timer coalescing: " + std::to_string(rc));
        }
    }
    else if (mode == 2 && g_highResTimersActive.load()) // BROWSER MODE
    {
        DWORD enableValue = 0;
        rc = RegSetValueExW(key, L"CoalescingTimerInterval", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&enableValue), sizeof(enableValue));
        
        if (rc == ERROR_SUCCESS)
        {
            g_highResTimersActive.store(false);
            Log("[DPC] Timer coalescing ENABLED (power efficiency for browser)");
        }
    }
    
    RegCloseKey(key);
}

void OptimizeDpcIsrLatency(DWORD pid, int mode)
{
    if (!g_dpcLatencyAvailable.load()) return;
    
    SetPriorityBoostControl(pid, mode);
    OptimizeThreadScheduling(pid, mode);
    SetTimerCoalescingControl(mode);
    
    if (mode == 1)
    {
        Log("[DPC] Full latency optimization applied (reduced input lag)");
    }
    else
    {
        Log("[DPC] Latency optimizations reverted to default");
    }
}

void CleanupProcessState(DWORD pid)
{
    bool cleanedSomething = false;
    
    {
        std::lock_guard lock(g_workingSetMtx);
        if (g_originalWorkingSets.erase(pid) > 0)
        {
            cleanedSomething = true;
        }
    }
    
    {
        std::lock_guard lock(g_dpcStateMtx);
        if (g_processesWithBoostDisabled.erase(pid) > 0)
        {
            cleanedSomething = true;
        }
    }
    
    {
        std::lock_guard lock(g_trimTimeMtx);
        if (g_lastTrimTimes.erase(pid) > 0)
        {
            cleanedSomething = true;
        }
    }
    
    if (cleanedSomething)
    {
        Log("[CLEANUP] Removed state for terminated process PID " + std::to_string(pid));
    }
}

bool IsUnderMemoryPressure()
{
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);

    if (!GlobalMemoryStatusEx(&ms))
        return false;

    uint64_t availMB = ms.ullAvailPhys >> 20;
    uint64_t totalMB = ms.ullTotalPhys >> 20;

    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);

    g_memTelemetry.lastAvailableMB.store(availMB, std::memory_order_relaxed);
    g_memTelemetry.lastCommitMB.store(
        (ms.ullTotalPhys - ms.ullAvailPhys) >> 20,
        std::memory_order_relaxed
    );
    g_memTelemetry.lastUpdateQpc.store(qpc.QuadPart, std::memory_order_relaxed);

    if (availMB < 2048)
        return true;

    if ((availMB * 100) / totalMB < 20)
        return true;

    return false;
}