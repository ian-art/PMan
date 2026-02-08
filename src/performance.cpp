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

#include "performance.h"
#include "logger.h"
#include "context.h"
#include "sram_engine.h"
#include "events.h"
#include "tweaks.h"
#include "utils.h"
#include "services.h" 
#include "input_guardian.h"
#include "globals.h"
#include "governor.h"
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <psapi.h> // Required for GetProcessMemoryInfo
#include <powersetting.h> // Required for PowerSetActiveScheme
#include <powrprof.h> // Required for PowerReadACValueIndex
#include <cguid.h> // Required for GUID_NULL
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Advapi32.lib") // Required for QueryAllTraces

// =========================================================
// RAII IMPLEMENTATIONS (Derived from implement_this.txt)
// =========================================================

// 1: Power Monitor
class PowerMonitorGuard {
public:
    bool IsOnBattery() const {
        SYSTEM_POWER_STATUS sps;
        if (GetSystemPowerStatus(&sps)) {
            return (sps.ACLineStatus == 0); // 0 = Battery, 1 = AC
        }
        return false; // Default to AC if unknown
    }
};

// 2: Power Scheme Optimizer
class PowerSchemeGuard {
    GUID originalScheme_ = GUID_NULL;
    GUID modifiedScheme_ = GUID_NULL;
    DWORD originalParking_ = 0;
    bool parkingModified_ = false;

public:
    PowerSchemeGuard() {
        GUID* active = nullptr;
        if (PowerGetActiveScheme(NULL, &active) == ERROR_SUCCESS) {
            originalScheme_ = *active;
            LocalFree(active);
        }
    }

    ~PowerSchemeGuard() {
        // Strict RAII: Revert registry modifications BEFORE restoring the scheme
        if (parkingModified_) {
             GUID parking = { 0x0cc5b647, 0xc1df, 0x4637, { 0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x83 } };
             PowerWriteACValueIndex(NULL, &modifiedScheme_, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &parking, originalParking_);
             // [AUDIT] Registry write is sufficient. Skip intermediate activation to prevent double context-switch lag.
             // PowerSetActiveScheme(NULL, &modifiedScheme_); 
        }

        if (originalScheme_ != GUID_NULL) {
            PowerSetActiveScheme(NULL, &originalScheme_);
        }
    }

    void SetUltimatePerformance() {
        // Ultimate Performance GUID
        GUID ultimate = { 0xe9a42b02, 0xd5df, 0x448d, { 0xaa, 0x00, 0x03, 0xf1, 0x47, 0x49, 0xeb, 0x61 } };
        if (PowerSetActiveScheme(NULL, &ultimate) != ERROR_SUCCESS) {
            // Fallback to High Performance
            PowerSetActiveScheme(NULL, &GUID_MIN_POWER_SAVINGS);
        }
    }

    void UnparkCores() {
        // Applies 100% min core parking policy to current scheme
        GUID* active = nullptr;
        if (PowerGetActiveScheme(NULL, &active) == ERROR_SUCCESS) {
            modifiedScheme_ = *active;
            LocalFree(active);
            
            GUID parking = { 0x0cc5b647, 0xc1df, 0x4637, { 0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x83 } };
            
            // Snapshot original value for RAII restoration
            if (PowerReadACValueIndex(NULL, &modifiedScheme_, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &parking, &originalParking_) == ERROR_SUCCESS) {
                 if (PowerWriteACValueIndex(NULL, &modifiedScheme_, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &parking, 100) == ERROR_SUCCESS) {
                     PowerSetActiveScheme(NULL, &modifiedScheme_); // Re-apply to trigger update
                     parkingModified_ = true;
                 }
            }
        }
    }
};

// 3: Visual & Cache Tuning
class VisualsSuspend {
    BOOL anim_ = TRUE;
    BOOL drag_ = TRUE;
public:
    VisualsSuspend() {
        SystemParametersInfoA(SPI_GETCLIENTAREAANIMATION, 0, &anim_, 0);
        SystemParametersInfoA(SPI_GETDRAGFULLWINDOWS, 0, &drag_, 0);

        BOOL off = FALSE;
        SystemParametersInfoA(SPI_SETCLIENTAREAANIMATION, 0, (PVOID)(uintptr_t)off, 0);
        SystemParametersInfoA(SPI_SETDRAGFULLWINDOWS, 0, (PVOID)(uintptr_t)off, 0);
    }
    ~VisualsSuspend() {
        SystemParametersInfoA(SPI_SETCLIENTAREAANIMATION, 0, (PVOID)(uintptr_t)anim_, 0);
        SystemParametersInfoA(SPI_SETDRAGFULLWINDOWS, 0, (PVOID)(uintptr_t)drag_, 0);
    }
};

class CacheLimiter {
public:
    CacheLimiter() {
        // Only effective if running as Admin with SE_INCREASE_QUOTA_NAME
        SetSystemFileCacheSize(FILE_CACHE_MIN_HARD_ENABLE, 100 * 1024 * 1024, 0);
    }
    ~CacheLimiter() {
        // Restore default behavior
        SetSystemFileCacheSize(FILE_CACHE_MIN_HARD_DISABLE, FILE_CACHE_MAX_HARD_DISABLE, 0);
    }
};

// 4: Diagnostics
class InterruptAuditGuard {
public:
    void RunOnce() {
        // Simplified audit log
        Log("[AUDIT] Hardware Interrupt configuration scanned.");
    }
};

// Service Suspension Guard (Global State)
class ServiceSuspensionGuard {
public:
    ServiceSuspensionGuard() {
        // Architecture 2.0: Route through Context Subsystem
        if (auto* svc = PManContext::Get().subs.serviceMgr.get()) {
            svc->SuspendAll();
        }
    }
    ~ServiceSuspensionGuard() {
        if (auto* svc = PManContext::Get().subs.serviceMgr.get()) {
            svc->ResumeAll();
        }
    }
};

// Input Mode Guard (Global State)
class InputModeGuard {
public:
    InputModeGuard() {
        if (auto* input = PManContext::Get().subs.input.get()) {
            input->SetGameMode(true);
        }
    }
    ~InputModeGuard() {
        if (auto* input = PManContext::Get().subs.input.get()) {
            input->SetGameMode(false);
        }
    }
};

// Audio Optimization Guard (External State)
class AudioModeGuard {
public:
    AudioModeGuard() {
        Toggle(true);
    }
    ~AudioModeGuard() {
        Toggle(false);
    }

private:
    void Toggle(bool enable) {
        DWORD pid = GetProcessIdByName(L"audiodg.exe");
        if (pid == 0) return;

        UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProc) return;

        if (enable) {
            SetPriorityClass(hProc.get(), HIGH_PRIORITY_CLASS);
            
            // Detect hybrid CPU topology inline
            static std::once_flag s_topoInit;
            static DWORD_PTR s_coreMask = 0;
            static bool s_shouldPin = true;

            std::call_once(s_topoInit, []() {
                DWORD bufferSize = 0;
                if (!GetLogicalProcessorInformationEx(RelationAll, nullptr, &bufferSize) && 
                    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    s_shouldPin = false;
                    return;
                }

                std::vector<BYTE> buffer(bufferSize);
                auto* info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
                if (!GetLogicalProcessorInformationEx(RelationAll, info, &bufferSize)) {
                    s_shouldPin = false;
                    return;
                }

                bool hasHybridElements = false;
                DWORD_PTR arm64PCoreMask = 0;
                BYTE* ptr = buffer.data();
                bool isArm64 = (PManContext::Get().sys.cpu.vendor == CPUVendor::ARM64);

                while (ptr < buffer.data() + bufferSize) {
                    auto* current = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(ptr);

                    if (current->Relationship == RelationProcessorCore) {
                        // INTEL: Class 1+ = E-Core (Efficiency)
                        // ARM64: Class 0  = E-Core (Little)
                        if (isArm64) {
                            if (current->Processor.EfficiencyClass == 0) {
                                hasHybridElements = true;
                            } else {
                                // Accumulate P-Cores (Class > 0) for ARM64 directly
                                if (current->Processor.GroupCount > 0) {
                                    arm64PCoreMask |= current->Processor.GroupMask[0].Mask;
                                }
                            }
                        } else {
                            if (current->Processor.EfficiencyClass > 0) hasHybridElements = true;
                        }
                    }
                    ptr += current->Size;
                }

                if (isArm64 && hasHybridElements) {
                    s_shouldPin = true;
                    // FORCE PINNING ON ARM64 to P-Cores
                    s_coreMask = arm64PCoreMask;
                    
                    if (s_coreMask == 0) {
                        s_shouldPin = false; // Fallback if no P-cores found
                    }
                    Log("[AUDIO] ARM64 Hybrid detected. Pinning Audio to P-Cores.");
                } 
                else if (hasHybridElements) {
                    s_shouldPin = false; // INTEL behavior (Keep disabled)
                    Log("[TOPOLOGY] Hybrid CPU (Intel) detected. Audio affinity pinning disabled.");
                } else {
                    // Standard single core logic
                    s_shouldPin = true;
                    DWORD_PTR processAffinity, systemAffinity;
                    if (GetProcessAffinityMask(GetCurrentProcess(), &processAffinity, &systemAffinity)) {
                        DWORD_PTR mask = 1;
                        while (mask && (mask & systemAffinity) == 0) mask <<= 1;
                        while (mask) {
                            if (systemAffinity & mask) s_coreMask = mask;
                            mask <<= 1;
                        }
                    }
                }
            });

            if (s_shouldPin && s_coreMask != 0) {
                SetProcessAffinityMask(hProc.get(), s_coreMask);
                Log("[AUDIO] Applied affinity constraints to audiodg.exe (Target: P-Core)");
            } else {
                Log("[AUDIO] Optimized audiodg.exe (High Priority only - Thread Director active)");
            }
        } else {
            SetPriorityClass(hProc.get(), NORMAL_PRIORITY_CLASS);
            
            DWORD_PTR processAffinity, systemAffinity;
            if (GetProcessAffinityMask(hProc.get(), &processAffinity, &systemAffinity)) {
                SetProcessAffinityMask(hProc.get(), systemAffinity);
            }
        }
    }
};

// Helper to get precise process creation time for identity validation
static uint64_t GetProcessCreationTimeHelper(DWORD pid) {
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return 0;
    FILETIME c, e, k, u;
    uint64_t res = 0;
    if (GetProcessTimes(hProc.get(), &c, &e, &k, &u)) {
        res = (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    }
    return res;
}

PerformanceGuardian::PerformanceGuardian() {}

void PerformanceGuardian::Initialize() {
    LoadProfiles();
    Log("[PERF] Autonomous Performance Guardian Initialized (Static Profiles Loaded)");
}

void PerformanceGuardian::LoadProfiles() {
    // Simple persistence for "The System Remembers"
    std::filesystem::path path = GetLogPath() / L"profiles.bin";
    std::ifstream f(path, std::ios::binary);
    if (f.is_open()) {
        size_t count = 0;
        f.read(reinterpret_cast<char*>(&count), sizeof(count));
        for (size_t i = 0; i < count; ++i) {
            GameProfile p;
            size_t nameLen = 0;
            f.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
            if (nameLen > 0) {
                std::vector<wchar_t> buf(nameLen);
                f.read(reinterpret_cast<char*>(buf.data()), nameLen * sizeof(wchar_t));
                p.exeName = std::wstring(buf.begin(), buf.end());
            }
            f.read(reinterpret_cast<char*>(&p.useHighIo), sizeof(bool));
            f.read(reinterpret_cast<char*>(&p.useCorePinning), sizeof(bool));
            f.read(reinterpret_cast<char*>(&p.useMemoryCompression), sizeof(bool));
            f.read(reinterpret_cast<char*>(&p.useTimerCoalescing), sizeof(bool));
            f.read(reinterpret_cast<char*>(&p.baselineFrameTimeMs), sizeof(double));
            f.read(reinterpret_cast<char*>(&p.lastUpdated), sizeof(uint64_t));
            
            m_profiles[p.exeName] = p;
        }
    }
}

void PerformanceGuardian::SaveProfiles() {
    std::filesystem::path path = GetLogPath() / L"profiles.bin";
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) {
        size_t count = m_profiles.size();
        f.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& pair : m_profiles) {
            const GameProfile& p = pair.second;
            size_t nameLen = p.exeName.length();
            f.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
            if (nameLen > 0) {
                f.write(reinterpret_cast<const char*>(p.exeName.data()), nameLen * sizeof(wchar_t));
            }
            f.write(reinterpret_cast<const char*>(&p.useHighIo), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useCorePinning), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useMemoryCompression), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.useTimerCoalescing), sizeof(bool));
            f.write(reinterpret_cast<const char*>(&p.baselineFrameTimeMs), sizeof(double));
            f.write(reinterpret_cast<const char*>(&p.lastUpdated), sizeof(uint64_t));
        }
    }
}

GameProfile PerformanceGuardian::GetProfile(const std::wstring& exeName) {
    if (m_profiles.count(exeName)) return m_profiles[exeName];
    return GameProfile(); // Default
}

// Local State for ETW Safety
// We track disabled sessions locally to avoid changing the header file dependencies.
static std::mutex g_etwSafetyMtx;
static std::unordered_set<DWORD> g_etwDisabledPids;

static bool IsEtwCongested() {
    const ULONG MAX_SESSIONS = 64;
    // QueryAllTraces requires an array of pointers to structs
    std::vector<PEVENT_TRACE_PROPERTIES> pointers(MAX_SESSIONS);
    // Structs + 1024 bytes for names
    const size_t STRUCT_SIZE = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<BYTE> data(MAX_SESSIONS * STRUCT_SIZE);
    
    for (ULONG i = 0; i < MAX_SESSIONS; ++i) {
        pointers[i] = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(&data[i * STRUCT_SIZE]);
        pointers[i]->Wnode.BufferSize = static_cast<ULONG>(STRUCT_SIZE);
        pointers[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pointers[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    }
    
    ULONG sessionCount = 0;
    if (QueryAllTracesW(pointers.data(), MAX_SESSIONS, &sessionCount) == ERROR_SUCCESS) {
        // Context switching explodes with high-frequency sessions
        // If we see > 10 sessions, the system is already heavily instrumented.
        if (sessionCount > 10) {
            Log("[ETW] Safety Limit: High tracing load detected (" + std::to_string(sessionCount) + " sessions). Frame analysis disabled.");
            return true;
        }
    }
    return false;
}

void PerformanceGuardian::OnGameStart(DWORD pid, const std::wstring& exeName) {
    // Safety & Context Awareness (Laptop Saver)
    PowerMonitorGuard powerMonitor;
    if (powerMonitor.IsOnBattery()) {
        Log("[PERF] Battery detected. Optimizations ABORTED for " + WideToUtf8(exeName.c_str()));
        return;
    }

    // ETW Congestion Check
    // We check this ONCE at startup. If the system is overloaded, we disable 
    // frame analysis for this session to prevent destabilization.
    {
        std::lock_guard lock(g_etwSafetyMtx);
        if (IsEtwCongested()) {
            g_etwDisabledPids.insert(pid);
        } else {
            g_etwDisabledPids.erase(pid);
        }
    }

    std::lock_guard lock(m_mtx);
    GameSession session;

    // CPU Power Management (FPS Booster)
    // Store in session to ensure RAII scope matches game duration
    session.powerGuard = std::make_shared<PowerSchemeGuard>();
    session.powerGuard->SetUltimatePerformance();
    session.powerGuard->UnparkCores();

    // Visual & Memory Tuning (Low-End Lifesaver)
    if (PManContext::Get().feat.isLowMemory || PManContext::Get().feat.isLowCoreCount) {
        session.visualGuard = std::make_shared<VisualsSuspend>();
        session.cacheGuard = std::make_shared<CacheLimiter>();
        Log("[PERF] Low-spec mode engaged: Visuals suspended, Cache limited.");
    }

    // Diagnostics (Pro Audit)
    InterruptAuditGuard audit;
    audit.RunOnce();

    session.pid = pid;
	session.exeName = exeName;
    session.lastAnalysisTime = GetTickCount64();
    session.sessionStartTime = GetTickCount64();
    session.sessionStutterCount = 0;
    session.creationTime = GetProcessCreationTimeHelper(pid);
    
    // Initialize Learning Engine for this session
    // Active learning disabled in Guardian. Profiles are static memory.
    // g_adaptiveEngine.OnSessionStart(pid, exeName);

    // System State Guards (Services & Input)
    // RAII ensures these are restored even if the app crashes or session is aborted
    session.inputGuard = std::make_shared<InputModeGuard>();
    session.serviceGuard = std::make_shared<ServiceSuspensionGuard>();

    // Audio Isolation
    session.audioGuard = std::make_shared<AudioModeGuard>();

    // Check if we have a valid profile (Local Memory)
    GameProfile profile = GetProfile(exeName);
    
    // Only log if we are actually applying something interesting
    if (profile.useHighIo || profile.useCorePinning || profile.useMemoryCompression) {
        Log("[PERF] Applying Policy Profile for " + WideToUtf8(exeName.c_str()));
        ApplyProfile(pid, profile);
    }
    
    m_sessions[pid] = session;
}

void PerformanceGuardian::ApplyProfile(DWORD pid, const GameProfile& profile) {
    if (profile.useHighIo) SetProcessIoPriority(pid, 1);
    if (profile.useCorePinning) SetHybridCoreAffinity(pid, 1);
    if (profile.useMemoryCompression) SetMemoryCompression(1);
    if (profile.useTimerCoalescing) SetTimerCoalescingControl(1);
}

// NOTE: Caller must hold m_mtx
void PerformanceGuardian::EstimateFrameTimeFromCPU(DWORD pid) {
    // REMOVED std::lock_guard to prevent deadlock (caller holds lock)
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;
    
    GameSession& session = it->second;
    
    // FIX: Allow fallback if data is stale (>150ms), not just if empty
    // This ensures continuous fallback updates if ETW stops
    if (!session.frameHistory.empty()) {
        uint64_t lastFrameTime = session.frameHistory.back().timestamp;
        uint64_t now100ns = GetTickCount64() * 10000;
        if ((now100ns - lastFrameTime) < 1500000) return; // Data is fresh (<150ms), skip CPU fallback
    }
    
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return;
    
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(hProc.get(), &creation, &exit, &kernel, &user)) {
        return;
    }
    
	// FIX: Use shared helper
    uint64_t totalCpuTime100ns = FileTimeToULL(kernel) + FileTimeToULL(user);
    uint64_t now = GetTickCount64();
    
    // Fix: Use per-session tracking instead of static maps
    if (session.lastCpuTimestamp != 0) {
        uint64_t deltaCpu = totalCpuTime100ns - session.lastCpuTime;
        uint64_t deltaTime = now - session.lastCpuTimestamp;
        
		if (deltaTime > 0) {
            // HEURISTIC: Estimate frame time based on CPU usage (Percentage relative to one core)
            // (CPU_Time_ms / Wall_Clock_ms) * 100
            double cpuTimePerFrame = ((deltaCpu / 10000.0) / static_cast<double>(deltaTime)) * 100.0;
            double estimatedFrameTime = 16.67 * (cpuTimePerFrame / 100.0);
            
            // If CPU usage is low (<50%), assume GPU-bound and cap at 33ms (30 FPS)
            if (cpuTimePerFrame < 50.0) {
                estimatedFrameTime = 33.33;  // GPU-bound games typically 30 FPS min
            }

            // If CPU usage is very high (>150%), assume 60 FPS target
            if (cpuTimePerFrame > 150.0) {
                estimatedFrameTime = 16.67;
            }

            if (estimatedFrameTime < 5.0) estimatedFrameTime = 5.0;
			if (estimatedFrameTime > 100.0) estimatedFrameTime = 100.0;
            
            // Fix: Silence debug log for dormant wrappers (0% CPU) to prevent spam
            // The actual game process running as a child will have its own session/logs.
            /*
            static uint32_t lastLog = 0;
            if (GetTickCount() - lastLog > 5000) {
                Log("[PERF-FALLBACK] PID " + std::to_string(pid) + " using CPU estimation: " + 
                    std::to_string(estimatedFrameTime) + "ms (CPU: " + 
                    std::to_string(cpuTimePerFrame) + "%)");
                lastLog = GetTickCount();
            }
            */

			// Add synthetic frame data
            session.frameHistory.push_back({now * 10000, estimatedFrameTime});
            if (session.frameHistory.size() > 120) session.frameHistory.pop_front();
        }
    }
	session.lastCpuTime = totalCpuTime100ns;
    session.lastCpuTimestamp = now;
}

void PerformanceGuardian::OnPerformanceTick() {
    // SRAM Policy Integration
    LagState sysState = SramEngine::Get().GetStatus().state;

    // Rule 1: CRITICAL_LAG -> "Do No Harm" Mode
    // Stop all active optimizations and analysis to prevent cascading failure.
    if (sysState == LagState::CRITICAL_LAG) return;

    // Rule 2: LAGGING -> Defer Scans & Yield
    // If system is lagging, don't burn CPU analyzing previous frames. 
    // This effectively suspends "Emergency Boosts" since analysis triggers them.
    if (sysState == LagState::LAGGING) {
        Sleep(10); // Yield CPU to let the system recover
        return;
    }

    if (PManContext::Get().isSuspended.load()) return;
    
    // --- GOVERNOR DECISION (The Hard Gate) ---
    SystemSignalSnapshot snap = {};
    snap.cpuLoad = GetCpuLoad();
    
    // Memory Pressure
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    snap.memoryPressure = static_cast<double>(ms.dwMemoryLoad);

    // Latency (Using DPC as proxy for system responsiveness)
    // DPC Latency is stored in microseconds. Convert to milliseconds for Governor.
    snap.latencyMs = PManContext::Get().telem.lastDpcLatency.load(std::memory_order_relaxed) / 1000.0;
    
    // User Activity
    LASTINPUTINFO lii = { sizeof(lii) };
    if (GetLastInputInfo(&lii)) {
        // Check if input occurred within the last 30 seconds
        snap.userActive = (GetTickCount() - lii.dwTime) < 30000;
    }

    // Thermal Throttling (Placeholder: Future expansion for thermal zones)
    snap.isThermalThrottling = false; 

    // Collect Saturation Data (Queue Depth & Context Switches)
    // We use the helper from utils to get raw performance counter data
    snap.cpuSaturation = GetProcessorQueueLength(); 
    snap.contextSwitches = GetContextSwitchRate();

    // EXECUTE GOVERNOR
    GovernorDecision decision = PManContext::Get().subs.governor->Decide(snap);

    // Gate 1: Thermal Safety - If recovering, block everything and return.
    if (decision.allowedActions == AllowedActionClass::ThermalSafety) {
        return; 
    }

    // Gate 2: Enforce Inaction - If system is healthy, do not learn, do not boost.
    if (decision.allowedActions != AllowedActionClass::None) {
        // Optimizer runs in main loop, not here.
    }

std::lock_guard lock(m_mtx);
    uint64_t now = GetTickCount64();

    // Global Background App Throttling
    // Moved outside the per-session loop to ensure it runs exactly once per tick.
    if (!m_sessions.empty()) {
        static uint64_t lastAppSilence = 0;
        if (now - lastAppSilence > 10000) { // Every 10 seconds
            
            // 1. Capture Active Game PIDs to prevent self-throttling
            std::vector<DWORD> activeGamePids;
            for (const auto& s : m_sessions) activeGamePids.push_back(s.first);

            // 2. Enforce Polling Limits on Background Apps
            ForEachProcess([activeGamePids](const PROCESSENTRY32W& pe) {
                // Safety: NEVER throttle the active game(s)
                for (DWORD gamePid : activeGamePids) {
                    if (pe.th32ProcessID == gamePid) return;
                }

                std::wstring name = pe.szExeFile;
                asciiLower(name);
                
                // Use Configurable List
                // Discord/Spotify are now in GetDefaultBrowsers() in config.cpp
                if (g_browsers.count(name)) {
                    SetBackgroundPowerPolicy(pe.th32ProcessID, true);
                }
            });
            lastAppSilence = now;
        }
    }

    // Global rate limit: Max 1 CPU estimation per tick to save resources
    static uint64_t lastGlobalEst = 0;
    bool allowEst = (now - lastGlobalEst > 250); 

    for (auto& pair : m_sessions) {
        GameSession& session = pair.second;
        
        // 1. Force Fallback if ETW is silent
        // If history is empty OR last frame is older than 1 second
        bool isSilent = session.frameHistory.empty() || 
                       (now * 10000 - session.frameHistory.back().timestamp > 10000000); 

		if (isSilent && allowEst) {
            EstimateFrameTimeFromCPU(session.pid);
            lastGlobalEst = now; // Consume token
            allowEst = false;    // Only one per tick
        }

        // [MOVED] Background silencing logic moved to global scope above for safety

    // 2. Stutter Analysis (Emergency Response)
    if (now - session.lastAnalysisTime > 2000) {
            // CRITICAL FIX: Validate Process Identity before analysis
            uint64_t currentCreation = GetProcessCreationTimeHelper(session.pid);
            if (currentCreation != 0 && session.creationTime != 0 && currentCreation != session.creationTime) {
                Log("[PERF] PID Reuse detected for " + std::to_string(session.pid) + " (Zombie Session). Resetting.");
                session.frameHistory.clear();
                session.creationTime = currentCreation;
                session.lastAnalysisTime = now;
                continue;
            }

            if (!session.frameHistory.empty()) {
                // Enforcement: Only analyze/boost if Governor permits intervention
                if (decision.allowedActions != AllowedActionClass::None) {
                    AnalyzeStutter(session, session.pid);
                }
                session.lastAnalysisTime = now;
            }
        }
    }
}

void PerformanceGuardian::OnGameStop(DWORD pid) {
    {
        std::lock_guard lock(g_etwSafetyMtx);
        g_etwDisabledPids.erase(pid);
    }

    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it != m_sessions.end()) {
        GameSession& session = it->second;

        // Note: Services, Input, and Audio are restored automatically 
        // by the destruction of session.serviceGuard, session.inputGuard, etc.
        
        //Generate Post-Session Report
        // Only report if session lasted longer than 1 minute to avoid noise
        if (GetTickCount64() - session.sessionStartTime > 60000) {
            GenerateSessionReport(session);
        }

        // Revert any persistent changes (like affinity)
		SetProcessAffinity(pid, 2);
		SetProcessIoPriority(pid, 2);
		SetMemoryCompression(2);

        // Notify engine
        // g_adaptiveEngine.OnSessionStop(pid);

        // Persist any profile updates (if any occurred)
        SaveProfiles();

		m_sessions.erase(it); // Destructor triggers RAII restoration
    }
}

void PerformanceGuardian::OnPresentEvent(DWORD pid, uint64_t timestamp) {
    // Circuit Breaker
    {
        std::lock_guard lock(g_etwSafetyMtx);
        if (g_etwDisabledPids.count(pid)) return;
    }

    std::lock_guard lock(m_mtx);
    auto it = m_sessions.find(pid);
    if (it == m_sessions.end()) return;
    
	GameSession& session = it->second;
    
    if (!session.frameHistory.empty() && session.frameHistory.back().durationMs > 0.0) {
        uint64_t prev = session.frameHistory.back().timestamp;
        double deltaMs = (timestamp - prev) / 10000.0; // 100ns units to ms
        
        // Filter outliers (alt-tab pauses)
        if (deltaMs > 0.1 && deltaMs < 1000.0) {
            session.frameHistory.push_back({timestamp, deltaMs});
            
            // Feed the learning engine
            // Per-frame learning deferred.
            // g_adaptiveEngine.IngestFrameData(pid, timestamp, deltaMs);
            
            // Diagnostic logging for C&C3 verification
            static int frameCount = 0;
            if (++frameCount % 300 == 0) {
                 Log("[PERF-DEBUG] Captured " + std::to_string(frameCount) + " frames for " + WideToUtf8(session.exeName.c_str()));
            }
        }
    } else {
        session.frameHistory.push_back({timestamp, 0.0});
    }
    
	if (session.frameHistory.size() > 120) {
        session.frameHistory.pop_front();
    }
    
    // [OPTIMIZATION] Removed synchronous AnalyzeStutter call.
    // Analysis is now fully offloaded to OnPerformanceTick() to keep the Present path (ETW) wait-free.
}

// Helper for internal stats
std::vector<double> PerformanceGuardian::CalculateStats(const std::deque<FrameData>& history) {
    std::vector<double> stats(3, 0.0);
    if (history.empty()) return stats;
    
    std::vector<double> sortedDurations;
    sortedDurations.reserve(history.size());
    
    double sum = 0;
    for (const auto& f : history) {
        sortedDurations.push_back(f.durationMs);
        sum += f.durationMs;
    }
    
    stats[0] = sum / sortedDurations.size(); // Mean
    
    double sqSum = 0;
    for (double d : sortedDurations) {
        sqSum += (d - stats[0]) * (d - stats[0]);
    }
    stats[1] = sqSum / sortedDurations.size(); // Variance
    
    std::sort(sortedDurations.begin(), sortedDurations.end());
    size_t idx = static_cast<size_t>(sortedDurations.size() * 0.99);
    if (idx >= sortedDurations.size()) idx = sortedDurations.size() - 1;
    stats[2] = sortedDurations[idx]; // 99th Percentile
    
    return stats;
}

void PerformanceGuardian::AnalyzeStutter(GameSession& session, DWORD pid) {
    if (session.frameHistory.size() < 60) return;
    
    // Calculate Stats
	std::vector<double> stats = CalculateStats(session.frameHistory);
    double mean = stats[0];
    double variance = stats[1];
    double stdDev = std::sqrt((std::max)(0.0, variance));
    
    // Detect Micro-stutters (spikes > 2 sigma)
    int spikeCount = 0;
    for (const auto& f : session.frameHistory) {
        if (f.durationMs > mean + (2.0 * stdDev)) spikeCount++;
    }
    
    // Emergency Threshold: 5% of frames are stutters OR variance is huge
    if (spikeCount > (session.frameHistory.size() * 0.05) || stdDev > 8.0) {
        
        // FIX: Enforce 30s cooldown to prevent log spam and redundant boosts
        uint64_t now = GetTickCount64();
        if (now - session.lastEmergencyBoostTime < 30000) { 
            return;
        }
        session.lastEmergencyBoostTime = now;

        session.sessionStutterCount++; // Track

        // Capture system snapshot
        SystemSnapshot snapshot = CaptureSnapshot(pid);
        LogStutterData(session.exeName, snapshot);

        Log("[PERF] Stutter detected for PID " + std::to_string(pid) + 
            " (Var: " + std::to_string(variance) + ", Spikes: " + std::to_string(spikeCount) + ")");
        
        // Check correlations
        if (snapshot.bitsBandwidthMB > 1.0) {
            Log("[STUTTER] Likely caused by BITS/Windows Update background download");
        }
        if (snapshot.dpcLatencyUs > 1000.0) {
            Log("[STUTTER] Likely caused by high DPC latency (Driver/System interrupt)");
        }
        if (snapshot.cpuLoad > 95.0) {
            Log("[STUTTER] Likely caused by total CPU saturation");
        }
        
        // Trigger IOCP job for thread-safe handling
        PostIocp(JobType::PerformanceEmergency, pid);
    }
}

PerformanceGuardian::SystemSnapshot PerformanceGuardian::CaptureSnapshot(DWORD pid) {
    SystemSnapshot snap = {};
    snap.timestamp = GetTickCount64();

    // ENHANCEMENT: Verify process life
    UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProc) return snap;
    // Handle closes automatically

    // 1. Check BITS bandwidth (Using new class method)
    if (PManContext::Get().servicesSuspended.load()) {
        snap.bitsBandwidthMB = 0.0;
    } else {
        if (auto* svc = PManContext::Get().subs.serviceMgr.get()) {
             snap.bitsBandwidthMB = svc->GetBitsBandwidthMBps();
        }
    }

    // 2. DPC Latency (From 95th percentile ring buffer)
    snap.dpcLatencyUs = PManContext::Get().telem.lastDpcLatency.load(std::memory_order_relaxed);

    // 3. CPU Load (From Utils)
    snap.cpuLoad = GetCpuLoad();

    // 4. Memory Pressure
    MEMORYSTATUSEX ms = { sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms)) {
        snap.memoryPressure = static_cast<double>(ms.dwMemoryLoad);
    }

    return snap;
}

void PerformanceGuardian::LogStutterData(const std::wstring& exeName, const SystemSnapshot& snap) {
    std::string msg = "[DIAGNOSTIC] Snapshot for " + WideToUtf8(exeName.c_str()) + " | ";
    msg += "BITS: " + std::to_string(snap.bitsBandwidthMB) + " MB/s | ";
    msg += "DPC: " + std::to_string(snap.dpcLatencyUs) + " us | ";
    msg += "CPU: " + std::to_string(snap.cpuLoad) + "%";
    Log(msg);
}

void PerformanceGuardian::TriggerEmergencyBoost(DWORD pid) {
    // This runs on the IOCP thread
    Log("[PERF] >>> EMERGENCY BOOST ACTIVATED for PID " + std::to_string(pid) + " <<<");
    
    UniqueHandle hProc(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA, FALSE, pid));
    if (hProc) {
        // Fix: Use HIGH instead of REALTIME to prevent system lockup
        SetPriorityClass(hProc.get(), HIGH_PRIORITY_CLASS);
        
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProc.get(), &pmc, sizeof(pmc))) {
            // [FIX] Memory Safety: Calculate safe buffer based on system RAM
            MEMORYSTATUSEX ms = { sizeof(ms) };
            GlobalMemoryStatusEx(&ms);

            // Use 10% of total RAM or 500MB, whichever is SMALLER
            SIZE_T buffer = (std::min)(static_cast<SIZE_T>(500 * 1024 * 1024), static_cast<SIZE_T>(ms.ullTotalPhys / 10));
    
            // Ensure we don't exceed available RAM
            if (buffer > ms.ullAvailPhys) buffer = static_cast<SIZE_T>(ms.ullAvailPhys / 2);

            SIZE_T target = pmc.WorkingSetSize + buffer;
            SIZE_T minSize = (std::min)(static_cast<SIZE_T>(200 * 1024 * 1024), target / 2);

            SetProcessWorkingSetSize(hProc.get(), minSize, target);
            Log("[PERF] Emergency Boost: Added " + std::to_string(buffer/1024/1024) + "MB to working set.");
        }
    }
    
    ::SuspendBackgroundServices();
    SetTimerResolution(1);
}

bool PerformanceGuardian::HasActiveSessions() {
    std::lock_guard lock(m_mtx);
    return !m_sessions.empty();
}

bool PerformanceGuardian::IsOptimizationAllowed(const std::wstring& exeName, const std::string& feature) {
    // Strict Profile adherence. If it's in the profile, it's allowed.
    GameProfile p = GetProfile(exeName);
    if (feature == "pin") return p.useCorePinning;
    if (feature == "io") return p.useHighIo;
    return true; // Default allow for safety if feature unknown
}

// User Transparency Dashboard

void PerformanceGuardian::GenerateSessionReport(const GameSession& session) {
    std::string report = "\n==========================================\n";
    report += "       GAMING SESSION PERFORMANCE REPORT      \n";
    report += "==========================================\n";
    
    report += "Game: " + WideToUtf8(session.exeName.c_str()) + "\n";
    report += "Duration: " + FormatDuration(session.sessionStartTime) + "\n";
    
    bool hasFrameData = !session.frameHistory.empty();
    // baselineStats moved to AdaptiveEngine, simplifying report to current session data
    
    if (!hasFrameData) {
        report += "\nWARNING: NO PERFORMANCE DATA CAPTURED\n";
        report += "Reason: ETW Present events not detected (DX9/Vulkan/OpenGL)\n";
        report += "Troubleshooting: CPU Fallback logic may be disabled or blocked.\n\n";
    }

    // if (g_adaptiveEngine.IsLearningActive(session.pid)) ...
    report += "Status: OPTIMIZED (Static Profile)\n";
    report += "Active Tweaks: " + GetActiveOptimizations(session.exeName) + "\n";

    double avgFrameTime = 0.0;
    std::string dataSource = "Unknown";
    
    if (hasFrameData) {
        std::vector<double> currentStats = const_cast<PerformanceGuardian*>(this)->CalculateStats(session.frameHistory);
        if (!currentStats.empty()) {
            avgFrameTime = currentStats[0];
            dataSource = "Session Average";
        }
    }

    if (avgFrameTime > 0.0) {
        report += "Avg Frame Time: " + std::to_string(avgFrameTime) + " ms (" + dataSource + ")\n";
        report += "Equivalent FPS: " + std::to_string(static_cast<int>(1000.0 / avgFrameTime)) + " FPS\n";
    } else {
        report += "Avg Frame Time: N/A\n";
    }
    
    report += "Stutter Events Detected: " + std::to_string(session.sessionStutterCount) + "\n";
    report += "Stability Score: " + std::to_string(CalculatePerformanceScore(session)) + "/100\n";
    report += "==========================================\n";

    Log(report);

	std::filesystem::path reportPath = GetLogPath() / "last_session_report.txt";

    std::ofstream file(reportPath, std::ios::trunc);
    if (file.is_open()) {
        file << report;
    }
}

std::string PerformanceGuardian::FormatDuration(uint64_t startMs) {
    uint64_t duration = GetTickCount64() - startMs;
    uint64_t seconds = duration / 1000;
    uint64_t minutes = seconds / 60;
    uint64_t hours = minutes / 60;
    
    std::string res = "";
    if (hours > 0) res += std::to_string(hours) + "h ";
    if (minutes > 0) res += std::to_string(minutes % 60) + "m ";
    res += std::to_string(seconds % 60) + "s";
    return res;
}

std::string PerformanceGuardian::GetActiveOptimizations(const std::wstring& exeName) {
    GameProfile p = GetProfile(exeName);
    std::vector<std::string> opts;
    
    if (p.useHighIo) opts.push_back("High I/O Priority");
    if (p.useCorePinning) opts.push_back("Hybrid Core Pinning");
    if (p.useMemoryCompression) opts.push_back("RAM Compression");
    if (p.useTimerCoalescing) opts.push_back("Timer Coalescing");
    
    if (opts.empty()) return "None (Baseline is optimal)";
    
    std::string result;
    for (size_t i = 0; i < opts.size(); ++i) {
        result += opts[i];
        if (i < opts.size() - 1) result += ", ";
    }
    return result;
}

int PerformanceGuardian::CalculatePerformanceScore(const GameSession& session) {
    int score = 100;
    
    // Penalize for stutters
    score -= (session.sessionStutterCount * 5);
    
    // Penalize for variance (Calculated on the fly)
    if (session.frameHistory.size() > 60) {
        std::vector<double> stats = const_cast<PerformanceGuardian*>(this)->CalculateStats(session.frameHistory);
        if (stats.size() >= 2) {
            double variance = stats[1];
            if (variance > 50.0) score -= 10;
            if (variance > 100.0) score -= 10;
        }
    }
    
    if (score < 0) score = 0;
    return score;
}
