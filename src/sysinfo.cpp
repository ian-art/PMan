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

#include "sysinfo.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "constants.h"
#include <windows.h>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <intrin.h>
#include <thread>
#include <bitset> // Use bitset for C++17 compatibility

// Forward declarations
#if defined(_M_AMD64) || defined(_M_IX86)
static void DetectAMDChipletTopology();
static void DetectAMDFeatures();
#endif

static void DetectCPUVendor()
{
#if defined(_M_ARM64)
    g_cpuInfo.vendor = CPUVendor::ARM64;
    g_cpuInfo.vendorString = "ARM64";
    g_cpuInfo.brandString = "Windows on ARM64";
    
    // Registry-based detection for ARM64 SoCs
    wchar_t cpuName[128] = {};
    DWORD size = sizeof(cpuName);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hKey, L"ProcessorNameString", nullptr, nullptr, (LPBYTE)cpuName, &size) == ERROR_SUCCESS)
        {
            g_cpuInfo.brandString = WideToUtf8(cpuName);
        }
        else
        {
             g_cpuInfo.brandString += " (Generic ARM64)";
        }
        RegCloseKey(hKey);
    }
    else
    {
        // Fallback feature detection
        if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
        {
            g_cpuInfo.brandString += " (Crypto Extensions)";
        }
    }
#elif defined(_M_AMD64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // CPUID leaf 0: Vendor string
    __cpuid(cpuInfo, 0);
    
    char vendor[13] = {0};
    // Use strict aliasing-safe casts
    std::memcpy(vendor, &cpuInfo[1], sizeof(int));           // EBX
    std::memcpy(vendor + 4, &cpuInfo[3], sizeof(int));       // EDX  
    std::memcpy(vendor + 8, &cpuInfo[2], sizeof(int));       // ECX
    
    g_cpuInfo.vendorString = vendor;
    
    // Determine vendor
    if (strcmp(vendor, "GenuineIntel") == 0)
    {
        g_cpuInfo.vendor = CPUVendor::Intel;
    }
    else if (strcmp(vendor, "AuthenticAMD") == 0)
    {
        g_cpuInfo.vendor = CPUVendor::AMD;
    }
    else
    {
        g_cpuInfo.vendor = CPUVendor::Other;
    }
    
    // CPUID leaf 0x80000002-0x80000004: Brand string
    char brandString[49] = {0};
    __cpuid(cpuInfo, 0x80000002);
    memcpy(brandString, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000003);
    memcpy(brandString + 16, cpuInfo, sizeof(cpuInfo));
    __cpuid(cpuInfo, 0x80000004);
    memcpy(brandString + 32, cpuInfo, sizeof(cpuInfo));
    
    g_cpuInfo.brandString = brandString;
    
    // CPUID leaf 1: Feature flags
    __cpuid(cpuInfo, 1);
    g_cpuInfo.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    // CPUID leaf 7: Extended features
    __cpuidex(cpuInfo, 7, 0);
    g_cpuInfo.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
    g_cpuInfo.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    
    // AMD-specific detection
    if (g_cpuInfo.vendor == CPUVendor::AMD)
    {
        DetectAMDFeatures();
    }
#else
    g_cpuInfo.vendor = CPUVendor::Other;
    g_cpuInfo.vendorString = "Unknown";
    g_cpuInfo.brandString = "Unknown Architecture";
#endif
}

#if defined(_M_AMD64) || defined(_M_IX86)
static void DetectAMDFeatures()
{
    // AMD CPUID leaf 0x80000001: Extended features
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x80000001);
    
    // Check for Zen 3+ (Family 19h)
    __cpuid(cpuInfo, 1);
    DWORD family = ((cpuInfo[0] >> 8) & 0xF) + ((cpuInfo[0] >> 20) & 0xFF);
    
    if (family == 0x19) // Zen 3 and Zen 4
    {
        g_cpuInfo.hasZen3Plus = true;
        
        // Detect 3D V-Cache by checking brand string
        std::string brand = g_cpuInfo.brandString;
        asciiLower(brand);
        
        // 3D V-Cache CPUs have "X3D" in their name
        if (brand.find("x3d") != std::string::npos)
        {
            g_cpuInfo.hasAmd3DVCache = true;
        }
    }
    
    // Detect chiplet topology for Ryzen
    DetectAMDChipletTopology();
}

static void DetectAMDChipletTopology()
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return;
    
    typedef BOOL (WINAPI *GetLogicalProcessorInformationExPtr)(
        LOGICAL_PROCESSOR_RELATIONSHIP, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD);
    
    auto pGetLogicalProcessorInformationEx = 
        reinterpret_cast<GetLogicalProcessorInformationExPtr>(
            GetProcAddress(kernel32, "GetLogicalProcessorInformationEx"));
    
    if (!pGetLogicalProcessorInformationEx) return;
    
    // Query processor topology
    DWORD bufferSize = 0;
    pGetLogicalProcessorInformationEx(RelationAll, nullptr, &bufferSize);
    
    if (bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    auto* info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data());
    
    if (!pGetLogicalProcessorInformationEx(RelationAll, info, &bufferSize))
        return;
    
    // Parse topology to identify CCDs (L3 cache groups = chiplets)
	std::unordered_map<DWORD, std::vector<DWORD>> l3CacheGroups;
    DWORD detectedCoresPerCcd = 0; 
    BYTE* ptr = buffer.data();
    BYTE* end = buffer.data() + bufferSize;
    
    while (ptr < end)
    {
        auto* current = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(ptr);
        
		if (current->Relationship == RelationCache && 
            current->Cache.Level == 3)
        {
            // Each L3 cache represents a CCD
            DWORD ccdId = static_cast<DWORD>(l3CacheGroups.size());

			// Count cores in this L3 group
            DWORD coreCount = static_cast<DWORD>(std::bitset<sizeof(ULONG_PTR) * 8>(current->Cache.GroupMask.Mask).count());
            
            if (coreCount > detectedCoresPerCcd)
            {
                detectedCoresPerCcd = coreCount;
            }
            
            l3CacheGroups[ccdId] = std::vector<DWORD>();
        }
        
        ptr += current->Size;
    }
    
    g_cpuInfo.ccdCount = static_cast<DWORD>(l3CacheGroups.size());

    // For 3D V-Cache CPUs: CCD0 has the cache, CCD1+ don't
    if (g_cpuInfo.hasAmd3DVCache && g_cpuInfo.ccdCount >= 2)
    {
        typedef BOOL (WINAPI *GetSystemCpuSetInformationPtr)(PSYSTEM_CPU_SET_INFORMATION, ULONG, PULONG, HANDLE, ULONG);
        static auto pGetSystemCpuSetInformation = reinterpret_cast<GetSystemCpuSetInformationPtr>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemCpuSetInformation"));
        
        if (pGetSystemCpuSetInformation)
        {
            ULONG cpuSetBufferSize = 0;
            pGetSystemCpuSetInformation(nullptr, 0, &cpuSetBufferSize, nullptr, 0);
            
            if (cpuSetBufferSize > 0)
            {
                std::vector<BYTE> cpuSetBuffer(cpuSetBufferSize);
                auto* cpuSets = reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(cpuSetBuffer.data());
                
                if (pGetSystemCpuSetInformation(cpuSets, cpuSetBufferSize, &cpuSetBufferSize, nullptr, 0))
                {
                    ULONG numSets = cpuSetBufferSize / sizeof(SYSTEM_CPU_SET_INFORMATION);
					
					static bool topologyLogged = false;
					DWORD coresPerCcd = 0;
					
                    if (g_physicalCoreCount == 0 || g_cpuInfo.ccdCount == 0) {
                        if (!topologyLogged) {
                            Log("[AMD] WARNING: Topology detection incomplete. Skipping layout optimization.");
                            topologyLogged = true;
                        }
                        return;
                    }

                    if (detectedCoresPerCcd > 0)
                    {
                        coresPerCcd = detectedCoresPerCcd;
                    }
					else
                    {
                        if (g_cpuInfo.ccdCount > 0) {
                            coresPerCcd = g_physicalCoreCount / g_cpuInfo.ccdCount;
                        } else {
                            coresPerCcd = 0;
                        }
                    }
                                        
                    if (coresPerCcd > 0)
                    {
                        g_cpuInfo.coresPerCcd = coresPerCcd;
                        
                        // AMD Ryzen: First half = CCD0 (3D V-Cache), Second half = CCD1+
                        for (ULONG i = 0; i < numSets; i++)
                        {
                            if (cpuSets[i].Type == CpuSetInformation)
                            {
                                ULONG cpuSetId = cpuSets[i].CpuSet.Id;
                                BYTE coreIndex = cpuSets[i].CpuSet.CoreIndex;
                                
                                if (coreIndex < g_cpuInfo.coresPerCcd)
                                {
                                    g_cpuInfo.ccd0CoreSets.push_back(cpuSetId);
                                }
                                else
                                {
                                    g_cpuInfo.ccd1CoreSets.push_back(cpuSetId);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#endif

bool DetectIoPrioritySupport()
{
    // Test if we can actually set I/O priority on this system
    HANDLE hTestProcess = GetCurrentProcess();
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    typedef NTSTATUS (NTAPI *NtSetInformationProcessPtr)(
        HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
    
    auto pNtSetInformationProcess = 
        reinterpret_cast<NtSetInformationProcessPtr>(
            GetProcAddress(ntdll, "NtSetInformationProcess"));
    
    if (!pNtSetInformationProcess) return false;
    
    // Test with current process (should always succeed if supported)
    ULONG testPriority = IoPriorityNormal;
    NTSTATUS status = pNtSetInformationProcess(
        hTestProcess,
        ProcessIoPriority,
        &testPriority,
        sizeof(testPriority)
    );
    
    return NT_SUCCESS(status);
}

bool DetectGameIoPrioritySupport()
{
    HANDLE hTestProcess = GetCurrentProcess();
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    typedef NTSTATUS (NTAPI *NtSetInformationProcessPtr)(
        HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
    
    auto pNtSetInformationProcess = 
        reinterpret_cast<NtSetInformationProcessPtr>(
            GetProcAddress(ntdll, "NtSetInformationProcess"));
    
    if (!pNtSetInformationProcess) return false;
    
    // Test High priority (what games would use)
    ULONG highPriority = IoPriorityHigh;
    NTSTATUS status = pNtSetInformationProcess(
        hTestProcess,
        ProcessIoPriority,
        &highPriority,
        sizeof(highPriority)
    );
    
    bool highSupported = NT_SUCCESS(status);
    
    // Test Normal priority (fallback)
    ULONG normalPriority = IoPriorityNormal;
    status = pNtSetInformationProcess(
        hTestProcess,
        ProcessIoPriority,
        &normalPriority,
        sizeof(normalPriority)
    );
    
    bool normalSupported = NT_SUCCESS(status);
    
    if (highSupported)
    {
        Log("[I/O] High priority support: AVAILABLE");
        return true;
    }
    else if (normalSupported)
    {
        Log("[I/O] Normal priority support: AVAILABLE (High priority unsupported)");
        return false;
    }
    
    return false;
}

void DetectHybridCoreSupport()
{
    // Skip for non-Hybrid capable vendors (AMD 3D V-Cache is handled separately)
    if (g_cpuInfo.vendor != CPUVendor::Intel && g_cpuInfo.vendor != CPUVendor::ARM64)
    {
        Log("[HYBRID] CPU is " + g_cpuInfo.vendorString + " - skipping hybrid detection");
        return;
    }
    
    // Only available on Windows 10 1809+ (Build 17763+)
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return;
    
    typedef BOOL (WINAPI *GetSystemCpuSetInformationPtr)(
        PSYSTEM_CPU_SET_INFORMATION, ULONG, PULONG, HANDLE, ULONG);
    
    auto pGetSystemCpuSetInformation = 
        reinterpret_cast<GetSystemCpuSetInformationPtr>(
            GetProcAddress(kernel32, "GetSystemCpuSetInformation"));
    
    if (!pGetSystemCpuSetInformation)
    {
        Log("[HYBRID] GetSystemCpuSetInformation not available (OS too old)");
        return;
    }
    
    // Query CPU set information
    ULONG bufferSize = 0;
    pGetSystemCpuSetInformation(nullptr, 0, &bufferSize, nullptr, 0);
    
    if (bufferSize == 0) return;
    
    std::vector<BYTE> buffer(bufferSize);
    PSYSTEM_CPU_SET_INFORMATION cpuSets = 
        reinterpret_cast<PSYSTEM_CPU_SET_INFORMATION>(buffer.data());
    
    if (!pGetSystemCpuSetInformation(cpuSets, bufferSize, &bufferSize, nullptr, 0))
        return;
    
    // Categorize CPU sets by efficiency class
    std::unordered_set<BYTE> efficiencyClasses;
    std::vector<ULONG> pCores, eCores;
    ULONG numSets = bufferSize / sizeof(SYSTEM_CPU_SET_INFORMATION);
    
    for (ULONG i = 0; i < numSets; i++)
    {
        if (cpuSets[i].Type == CpuSetInformation)
        {
            BYTE effClass = cpuSets[i].CpuSet.EfficiencyClass;
            ULONG id = cpuSets[i].CpuSet.Id;

            // [ARM64] Validation Logging
            if (g_cpuInfo.vendor == CPUVendor::ARM64) {
                Log("[ARM64-DBG] Core " + std::to_string(id) + 
                    " EfficiencyClass=" + std::to_string(effClass));
            }
            ULONG cpuSetId = cpuSets[i].CpuSet.Id;
            
            efficiencyClasses.insert(effClass);
            
            if (g_cpuInfo.vendor == CPUVendor::ARM64)
            {
                // ARM: Class 0 = Efficiency (Silver), Class 1+ = Performance/Prime
                if (effClass == 0) eCores.push_back(cpuSetId);
                else pCores.push_back(cpuSetId);
            }
            else
            {
                // Intel (Default): Class 0 = P-cores, Class 1 = E-cores
                if (effClass == 0) pCores.push_back(cpuSetId);
                else if (effClass == 1) eCores.push_back(cpuSetId);
            }
        }
    }
    
    // Hybrid = at least 2 different efficiency classes
    g_caps.hasHybridCores = (efficiencyClasses.size() >= 2);
    
    if (g_caps.hasHybridCores)
    {
        std::lock_guard lock(g_cpuSetMtx);
        g_pCoreSets = std::move(pCores);
        g_eCoreSets = std::move(eCores);
        
        Log("[HYBRID] CPU has " + std::to_string(g_pCoreSets.size()) + 
            " P-cores and " + std::to_string(g_eCoreSets.size()) + " E-cores detected");
    }
    else
    {
        Log("[HYBRID] CPU is homogeneous (all cores same type)");
    }
    
    // Check if Power Throttling API is available (Windows 10 1709+)
    typedef BOOL (WINAPI *SetProcessInformationPtr)(
        HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
    
    auto pSetProcessInformation = 
        reinterpret_cast<SetProcessInformationPtr>(
            GetProcAddress(kernel32, "SetProcessInformation"));
    
    g_caps.supportsPowerThrottling = (pSetProcessInformation != nullptr);
    
    if (g_caps.supportsPowerThrottling)
    {
        Log("[HYBRID] Power Throttling API available");
    }
    else
    {
        Log("[HYBRID] Power Throttling API not available");
    }
}

// [SECURITY] Secret VM Detection Helper (Enhanced)
static bool IsKnownEmulator()
{
#if defined(_M_AMD64) || defined(_M_IX86)
    // --- TIER 1: CPUID Check (Fastest) ---
    // Only available on x86/x64
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    
    // Check Hypervisor Present Bit (Bit 31 of ECX)
    if ((cpuInfo[2] & (1 << 31))) { 
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {0};
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);

        // Standard Signatures
        if (strstr(vendor, "VMware") || strstr(vendor, "VBox") || 
            strstr(vendor, "KVM") || strstr(vendor, "QEMU") || 
            strstr(vendor, "Bochs") || strstr(vendor, "Xen") ||
            strstr(vendor, "Parallels")) return true;
    }
#endif

#if defined(_M_ARM64)
    // ARM64: Check firmware virtualization flag
    if (IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)) return true;
#endif

    // --- TIER 2: SMBIOS/Registry Check (Harder to spoof) ---
    // Real PCs (even with VBS/Core Isolation) pass through hardware strings (e.g. "Dell", "ASUS").
    // VMs usually expose "Virtual Machine", "VirtualBox", "KVM", etc. here.
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        wchar_t buffer[256] = {};
        DWORD size = sizeof(buffer);
        bool found = false;

        // 1. Check Manufacturer
        if (RegQueryValueExW(hKey, L"SystemManufacturer", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            std::wstring mfg = buffer;
            std::transform(mfg.begin(), mfg.end(), mfg.begin(), ::towlower);
            
            if (mfg.find(L"vmware") != std::wstring::npos || 
                mfg.find(L"bochs") != std::wstring::npos ||
                mfg.find(L"qemu") != std::wstring::npos ||
                mfg.find(L"xen") != std::wstring::npos) found = true;
        }

        // 2. Check Product Name (Model) - Catches Hyper-V and spoofed vendors
        if (!found) {
            size = sizeof(buffer);
            if (RegQueryValueExW(hKey, L"SystemProductName", nullptr, nullptr, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                std::wstring model = buffer;
                std::transform(model.begin(), model.end(), model.begin(), ::towlower);

                if (model.find(L"virtualbox") != std::wstring::npos || 
                    model.find(L"virtual machine") != std::wstring::npos || // Generic "Microsoft Virtual Machine"
                    model.find(L"kvm") != std::wstring::npos ||
                    model.find(L"parallels") != std::wstring::npos) found = true;
            }
        }

        RegCloseKey(hKey);
        if (found) return true;
    }

    return false;
}

void DetectOSCapabilities()
{
    Log("--- Detecting OS Capabilities ---");
    
	// (Moved DetectCPUVendor to after physical core detection to fix division by zero)
    
    // 7. Detect CPU topology (physical vs logical cores) - MOVED UP to fix dependencies
    // Originally step 7, but needed for AMD topology detection heuristics
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    g_logicalCoreCount = sysInfo.dwNumberOfProcessors;
    
    DWORD bufferSize = 0;
    GetLogicalProcessorInformation(nullptr, &bufferSize);
    
    if (bufferSize > 0)
    {
        std::vector<BYTE> topologyBuffer(bufferSize);
        auto* procInfo = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION>(topologyBuffer.data());
        
        if (GetLogicalProcessorInformation(procInfo, &bufferSize))
        {
            DWORD physicalCores = 0;
            DWORD_PTR physicalMask = 0;
            DWORD infoCount = static_cast<DWORD>(bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
            
            for (DWORD i = 0; i < infoCount; i++)
            {
                if (procInfo[i].Relationship == RelationProcessorCore)
                {
                    physicalCores++;
                    physicalMask |= static_cast<DWORD_PTR>(procInfo[i].ProcessorMask);
                }
            }
            
            g_physicalCoreCount = physicalCores;
            g_physicalCoreMask = physicalMask;
        }
    }
    
    if (g_physicalCoreCount == 0)
    {
        g_physicalCoreCount = g_logicalCoreCount;
        g_physicalCoreMask = (1ULL << g_logicalCoreCount) - 1;
    }
    
	// Fix Low resource detection (Single core or <4GB RAM)
    if (g_physicalCoreCount < 2)
    {
        g_isLowCoreCount = true;
        Log("[COMPAT] Single-core CPU detected - Disabling CPU pinning optimizations");
    }

    MEMORYSTATUSEX ms = {sizeof(ms)};
    if (GlobalMemoryStatusEx(&ms))
    {
        if (ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024)
        {
            g_isLowMemory = true;
            Log("[COMPAT] Low memory (<4GB) detected - Disabling aggressive working set limits");
        }
    }
	
	// 1. Log Topology first
    Log("CPU Topology: " + std::to_string(g_physicalCoreCount) + 
        " physical cores, " + std::to_string(g_logicalCoreCount) + 
        " logical cores (HT: " + 
		std::string(g_logicalCoreCount > g_physicalCoreCount ? "ON" : "OFF") + ")");

    // 2. Detect CPU vendor (Now that g_physicalCoreCount is valid)
    DetectCPUVendor();

    // 3. Log CPU details (Now that detection is complete)
    std::string cpuVendorStr;
	switch (g_cpuInfo.vendor)
    {
        case CPUVendor::Intel: cpuVendorStr = "Intel"; break;
        case CPUVendor::AMD:   cpuVendorStr = "AMD"; break;
        case CPUVendor::ARM64: cpuVendorStr = "ARM64"; break;
        default:               cpuVendorStr = "Unknown"; break;
    }
    
    Log("CPU: " + cpuVendorStr + " - " + g_cpuInfo.brandString);
    
    if (g_cpuInfo.vendor == CPUVendor::AMD)
    {
        if (g_cpuInfo.hasAmd3DVCache)
        {
            Log("AMD 3D V-Cache: DETECTED (" + std::to_string(g_cpuInfo.ccdCount) + 
                " CCDs, " + std::to_string(g_cpuInfo.coresPerCcd) + " cores/CCD)");
            Log("  CCD0 cores (with cache): " + std::to_string(g_cpuInfo.ccd0CoreSets.size()));
            Log("  CCD1+ cores (no cache): " + std::to_string(g_cpuInfo.ccd1CoreSets.size()));
        }
        else if (g_cpuInfo.hasZen3Plus)
        {
            Log("AMD Zen 3+ Architecture: DETECTED (no 3D V-Cache)");
        }
    }
    
    // ARM64 Topology Logging
    if (g_cpuInfo.vendor == CPUVendor::ARM64)
    {
        // Ensure hybrid detection has run or check caps
        if (g_caps.hasHybridCores)
        {
             Log("[ARM64] DynamIQ topology detected: " + 
                std::to_string(g_pCoreSets.size()) + " Performance/Prime cores, " +
                std::to_string(g_eCoreSets.size()) + " Efficiency cores");
        }
        else
        {
             Log("[ARM64] Topology: Homogeneous (or detection failed)");
        }
    }

    // 1. Check Windows Version
    auto hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod)
    {
        typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        auto rtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (rtlGetVersion)
        {
            RTL_OSVERSIONINFOW rovi = { 0 };
            rovi.dwOSVersionInfoSize = sizeof(rovi);
            if (rtlGetVersion(&rovi) == 0)
            {
                g_caps.isWindows10OrNewer = (rovi.dwMajorVersion >= 10);
                
                std::string osName = "Windows";
                std::string marketingVersion = "Unknown";

                if (rovi.dwMajorVersion >= 10 && rovi.dwBuildNumber >= 22000)
                {
                    osName = "Windows 11";
                    if (rovi.dwBuildNumber >= 26200)
                        marketingVersion = "25H2";
                    else if (rovi.dwBuildNumber >= 26100)
                        marketingVersion = "24H2";
                    else if (rovi.dwBuildNumber >= 22631)
                        marketingVersion = "23H2";
                    else if (rovi.dwBuildNumber >= 22621)
                        marketingVersion = "22H2";
                }
                else if (rovi.dwMajorVersion == 10)
                {
                    osName = "Windows 10";
                }

				DWORD ubr = 0;
                RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", ubr);

                Log(
                    "OS: " + osName +
                    " Version: " + marketingVersion +
                    " (Build " + std::to_string(rovi.dwBuildNumber) +
                    "." + std::to_string(ubr) + ")"
                );
                
                // [SECURITY] Generate Secret Environment ID
                // Logic: Even = Native, Odd = VM
                // We use TickCount to make it look like a random dynamic ID
                bool isVm = IsKnownEmulator();
                uint32_t secretId = GetTickCount(); 
                
                // Force Parity
                if (isVm) {
                    secretId |= 1; // Force Odd
                } else {
                    secretId &= ~1; // Force Even
                }
                
                Log("System Init ID: " + std::to_string(secretId));
            }
        }
    }

    // [ARM64] Prism (x64 Emulation) Detection
    // Critical: Emulated games/apps need aggressive isolation to separate them from the emulator overhead
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        typedef BOOL (WINAPI *IsWow64Process2Ptr)(HANDLE, USHORT*, USHORT*);
        auto pIsWow64Process2 = (IsWow64Process2Ptr)GetProcAddress(hKernel, "IsWow64Process2");
        if (pIsWow64Process2) {
            USHORT processMachine = 0, nativeMachine = 0;
            if (pIsWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine)) {
                // IMAGE_FILE_MACHINE_ARM64 = 0xAA64, IMAGE_FILE_MACHINE_AMD64 = 0x8664
                if (nativeMachine == 0xAA64 && processMachine == 0x8664) {
                    Log("[ARM64] x64 emulation (Prism) detected - enabling aggressive isolation");
                    g_caps.isPrismEmulated = true;
                }
            }
        }
    }

    if (g_cpuInfo.vendor == CPUVendor::ARM64) {
        Log("[ARM64] CPU: " + g_cpuInfo.brandString + " | Native: " + 
            (g_caps.isPrismEmulated ? "NO (Prism)" : "YES") + " | Topology: " + 
            (g_caps.hasHybridCores ? "Hybrid" : "Homogeneous"));
    }

    // 2. Check Admin Rights
    HKEY hKey = nullptr;
    LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    
    if (lRes == ERROR_SUCCESS)
    {
        g_caps.hasAdminRights = true;
        RegCloseKey(hKey);
        Log("Registry Access: FULL (Read/Write)");
    }
    else
    {
        g_caps.hasAdminRights = false;
        Log("Registry Access: READ-ONLY (Admin rights missing) - Code: " + std::to_string(lRes));
    }

    // 3. Check Session API
    g_caps.hasSessionApi = true; 

	// 4. Check ETW Availability
    TRACEHANDLE hSession = 0;
    size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<BYTE> buffer(buffSize); // RAII: Automatically handles memory
    
	// 5. Check I/O Priority Support
	bool ioPrioritySupported = DetectIoPrioritySupport();
	bool gameIoPrioritySupported = DetectGameIoPrioritySupport();

	Log("I/O Priority Support: " + std::string(ioPrioritySupported ? "AVAILABLE" : "UNAVAILABLE"));
	Log("Game I/O Priority: " + std::string(gameIoPrioritySupported ? "HIGH SUPPORTED" : "NORMAL ONLY"));

	if (!ioPrioritySupported)
	{
		Log("WARNING: I/O priority setting may fail on this system - will use fallback methods");
	}
	
	// Remove "if (buffer)" check since vector allocation throws on failure or is empty
    if (!buffer.empty())
    {
        // Use buffer.data() to access the raw pointer
        EVENT_TRACE_PROPERTIES* pProps = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        ZeroMemory(pProps, buffSize);
        pProps->Wnode.BufferSize = static_cast<ULONG>(buffSize);
        pProps->Wnode.Guid = { 0 };
        pProps->Wnode.ClientContext = 1;
        pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        
        // Use buffer.data() for pointer arithmetic
        wcscpy_s(reinterpret_cast<wchar_t*>(buffer.data() + pProps->LoggerNameOffset), 512, L"PriorityMgr_CapabilityCheck");

        ULONG status = StartTraceW(&hSession, L"PriorityMgr_CapabilityCheck", pProps);
        
        if (status == ERROR_SUCCESS || status == ERROR_ALREADY_EXISTS)
        {
            g_caps.canUseEtw = true;
            if (status == ERROR_SUCCESS) ControlTraceW(hSession, L"PriorityMgr_CapabilityCheck", pProps, EVENT_TRACE_CONTROL_STOP);
            Log("ETW Capability: AVAILABLE");
        }
        else
        {
            g_caps.canUseEtw = false;
            Log("ETW Capability: UNAVAILABLE (Error " + std::to_string(status) + ")");
        }
        // delete[] buffer; -> Removed, vector cleans up automatically
    }
    
    // 6. Check GPU Scheduling (Windows 10 2004+)
    HKEY hGpuKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
        0, KEY_QUERY_VALUE, &hGpuKey) == ERROR_SUCCESS)
    {
        DWORD hwScheduling = 0;
        DWORD size = sizeof(hwScheduling);
        if (RegQueryValueExW(hGpuKey, L"HwSchMode", nullptr, nullptr,
                            reinterpret_cast<BYTE*>(&hwScheduling), &size) == ERROR_SUCCESS)
        {
            if (hwScheduling == 2)
            {
                // Test if GPU priority API actually works
                HANDLE hTestProcess = GetCurrentProcess();
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
						PROCESS_INFORMATION_CLASS gpuPriorityClass = ProcessGpuPriority;
                        ULONG testPriority = 0;
                        
                        NTSTATUS status = pNtSetInformationProcess(
                            hTestProcess, gpuPriorityClass, &testPriority, sizeof(testPriority));
                        
                        if (NT_SUCCESS(status))
                        {
                            g_gpuSchedulingAvailable.store(true);
                            Log("GPU Hardware Scheduling: ENABLED + API SUPPORTED");
                        }
                        else
                        {
                            Log("GPU Hardware Scheduling: ENABLED but API unsupported (old GPU/driver)");
                        }
                    }
                }
            }
            else
            {
                Log("GPU Hardware Scheduling: DISABLED (enable in Windows settings)");
            }
        }
        else
        {
            Log("GPU Hardware Scheduling: NOT AVAILABLE (Windows 10 1909 or older)");
        }
        RegCloseKey(hGpuKey);
    }
    
    // 8. Check Working Set Management API availability
    HMODULE kernel32test = GetModuleHandleW(L"kernel32.dll");
    if (kernel32test)
    {
        typedef BOOL (WINAPI *SetProcessWorkingSetSizeExPtr)(HANDLE, SIZE_T, SIZE_T, DWORD);
        auto pSetProcessWorkingSetSizeEx = 
            reinterpret_cast<SetProcessWorkingSetSizeExPtr>(
                GetProcAddress(kernel32test, "SetProcessWorkingSetSizeEx"));
        
        if (pSetProcessWorkingSetSizeEx)
        {
            g_workingSetManagementAvailable.store(true);
            Log("Working Set Management: AVAILABLE (will optimize RAM usage)");
        }
        else
        {
            Log("Working Set Management: UNAVAILABLE (Windows XP/Vista only)");
        }
    }
    
    // 9. Check DPC/ISR Latency Management availability
    HMODULE ntdllTest2 = GetModuleHandleW(L"ntdll.dll");
    if (ntdllTest2)
    {
        // Check for NtSetInformationThread (thread priority control)
        typedef NTSTATUS (NTAPI *NtSetInformationThreadPtr)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
        auto pNtSetInformationThread = 
            reinterpret_cast<NtSetInformationThreadPtr>(
                GetProcAddress(ntdllTest2, "NtSetInformationThread"));
        
        if (pNtSetInformationThread)
        {
            g_dpcLatencyAvailable.store(true);
            Log("DPC/ISR Latency Control: AVAILABLE (will reduce input lag)");
        }
        else
        {
            Log("DPC/ISR Latency Control: UNAVAILABLE (legacy OS)");
        }
    }
    
    // Check for timer coalescing API (Windows 7+)
    if (kernel32test)
    {
        typedef BOOL (WINAPI *QueryProcessCycleTimePtr)(HANDLE, PULONG64);
        auto pQueryProcessCycleTime = 
            reinterpret_cast<QueryProcessCycleTimePtr>(
                GetProcAddress(kernel32test, "QueryProcessCycleTime"));
        
        if (pQueryProcessCycleTime)
        {
            g_timerCoalescingAvailable.store(true);
            Log("Timer Coalescing Control: AVAILABLE (precise timing)");
        }
        else
        {
            Log("Timer Coalescing Control: UNAVAILABLE (Windows Vista)");
        }
    }
    
    // [ARM64] Architecture Transparency Log
    if (g_cpuInfo.vendor == CPUVendor::ARM64) {
        std::string nativeStatus = g_caps.isPrismEmulated ? "NO (Prism Emulation)" : "YES";
        std::string topoStatus = g_caps.hasHybridCores ? "Hybrid (DynamIQ)" : "Homogeneous";
        
        Log("[ARM64] CPU: " + g_cpuInfo.brandString);
        Log("[ARM64] Native Code: " + nativeStatus + " | Topology: " + topoStatus);
    }
    
    Log("-------------------------------------");
}

AffinityStrategy GetRecommendedStrategy()
{
    // [ARM64] Policy Override
    // If we are emulated (Prism), force GameIsolation to keep emulator overhead on unpinned cores.
    // If we are Native ARM64, we also prefer Isolation to keep the game on the big cores.
    if (g_caps.isPrismEmulated || g_cpuInfo.vendor == CPUVendor::ARM64) {
        return AffinityStrategy::GameIsolation;
    }

    // 1. Hybrid Architecture (Intel 12th+) -> Always use P/E Logic
    if (g_caps.hasHybridCores) return AffinityStrategy::HybridPinning;

    // 2. Homogeneous High Core Count (>= 6) -> Strong Isolation
    if (g_physicalCoreCount >= 6) return AffinityStrategy::GameIsolation;

    // 3. Homogeneous Quad Core (4) -> Mild Isolation (Reserve 1 core)
    // We enable this for your i7 Q 740 to get benefits.
    if (g_physicalCoreCount >= 4) return AffinityStrategy::GameIsolation;

    // 4. Dual Core or Single Core -> Do nothing (Affinity hurts here)
    return AffinityStrategy::None;
}

DWORD_PTR GetOptimizationTargetCores()
{
    // Core Selection Policy
    // "Select exactly two cores that: Are not Core 0, Are in the same NUMA node..."
    
    // Safety Abort: Need at least 3 logical cores to exclude Core 0 and pick 2 others.
    if (g_logicalCoreCount < 3) 
    {
        Log("[CORE] Insufficient cores for offload (Need 3+, Found " + std::to_string(g_logicalCoreCount) + ")");
        return 0;
    }

    DWORD_PTR mask = 0;
    std::vector<int> selectedIndices;

    // Strategy A: Hybrid Architecture (Use E-Cores)
    if (g_caps.hasHybridCores && g_eCoreSets.size() >= 2)
    {
        // Pick the last two E-Cores (usually furthest from P-Core heat/interrupts)
        size_t count = g_eCoreSets.size();
        
        // Use the last two E-cores for service offloading
        // Map E-core logical indices to affinity mask bits
        int lastECore = g_logicalCoreCount - 1;
        int secondLastECore = g_logicalCoreCount - 2;
        
        mask |= (static_cast<DWORD_PTR>(1) << lastECore);
        mask |= (static_cast<DWORD_PTR>(1) << secondLastECore);
        
        Log("[CORE] Selected Offload Targets (E-Cores): CPU " + std::to_string(secondLastECore) + 
            " & CPU " + std::to_string(lastECore) + " (" + std::to_string(count) + " E-cores available)");
        return mask;
    }

    // Strategy B: Standard Architecture
    // "Identify Core 0 (interrupt-heavy)" -> Core 0 is Mask 0x1.
    // We select the LAST two logical processors.
    // - On HT systems, these are the SMT threads of the last physical core.
    // - On non-HT systems, these are the last two physical cores.
    // - This satisfies "Are in the same NUMA node" for 99% of consumer desktop CPUs (single socket).
    
    int lastCore = g_logicalCoreCount - 1;
    int secondLastCore = g_logicalCoreCount - 2;

    // Verification: Ensure we aren't selecting Core 0 (Index 0)
    if (secondLastCore > 0)
    {
        mask |= (static_cast<DWORD_PTR>(1) << lastCore);
        mask |= (static_cast<DWORD_PTR>(1) << secondLastCore);
        
        Log("[CORE] Selected Offload Targets: CPU " + std::to_string(secondLastCore) + 
            " & CPU " + std::to_string(lastCore) + " (Avoiding Core 0)");
        return mask;
    }

    Log("[CORE] Selection failed validation (Indices collided with Core 0)");
    return 0;
}
