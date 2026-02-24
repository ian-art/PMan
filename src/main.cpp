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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "types.h"
#include "constants.h"
#include "globals.h"
#include "logger.h"
#include "utils.h"
#include "config.h"
#include "sysinfo.h"
#include "policy.h"
#include "events.h"
#include "tweaks.h"
#include "services.h"
#include "services_watcher.h"
#include "restore.h"
#include "static_tweaks.h"
#include "memory_optimizer.h"
#include "network_monitor.h"
#include "input_guardian.h"
#include "gui_manager.h"
#include "dark_mode.h"
#include "log_viewer.h"
#include "sram_engine.h"
#include "lifecycle.h"
#include "executor.h" // [FIX] Required for Executor::Shutdown
#include "policy_optimizer.h" // [FIX] Defines PolicyOptimizer
#include "governor.h"
#include "consequence_evaluator.h"
#include "predictive_model.h" // Machine learning state prediction
#include "decision_arbiter.h"
#include "shadow_executor.h"
#include "reality_sampler.h"
#include "prediction_ledger.h"
#include "confidence_tracker.h"
#include "sandbox_executor.h"
#include "intent_tracker.h" // [FIX] Added missing include
#include "outcome_guard.h"
#include "authority_budget.h"
#include "provenance_ledger.h"
#include "policy_contract.h"
#include "external_verdict.h"
#include "context.h"
#include "tray_animator.h"
#include "ipc_server.h"
#include "responsiveness_manager.h"
#include "telemetry_agent.h" // Telemetry Agent
#include "heartbeat.h" // Watchdog Heartbeat
#include "crash_reporter.h" // Crash Reporting
#include "autonomous_engine.h" // Autonomous Engine Orchestrator
#include <thread>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>
#include <objbase.h> // Fixed: Required for CoInitialize
#include <powrprof.h>
#include <pdh.h>
#include <shellapi.h> // Required for CommandLineToArgvW
#include <commctrl.h> // For Edit Control in Live Log
// <deque> removed — owned by worker_thread.cpp
#include <mutex>
#include <condition_variable>
#include <functional>
#include <dwmapi.h>   // Required for DWM Dark Mode
#include <uxtheme.h>  // Required for Theme definitions
#include <array>

#pragma comment(lib, "PowrProf.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib") // For BITS monitoring
#pragma comment(lib, "Gdi32.lib") // Required for CreateFontW/DeleteObject
#pragma comment(lib, "Comctl32.lib") // Required for TaskDialog
#pragma comment(lib, "Dwmapi.lib") // DWM
#pragma comment(lib, "Uxtheme.lib") // UxTheme

// Force Linker to embed Manifest for Visual Styles (Required for TaskDialog)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// GuiManager::OpenPolicyTab declared in gui_manager.h

// GLOBAL VARIABLE
HINSTANCE g_hInst = nullptr;
static UINT g_wmTaskbarCreated = 0;

// ID_TRAY_EXPORT_LOG defined in constants.h

std::atomic<bool> g_isCheckingUpdate{false};
// [FIX] RAII: Replaced raw GUID* with smart pointer to prevent leak/manual management
struct LocalFreeDeleter { void operator()(void* p) const { if (p) LocalFree(p); } };
static std::unique_ptr<GUID, LocalFreeDeleter> g_pSleepScheme;
static UniqueHandle g_hGuardProcess; // Handle to the watchdog process
uint64_t g_resumeStabilizationTime = 0; // Replaces detached sleep thread;

// Removed LaunchProcessAsync (Dead Code / Unsafe Detach)
// All process launches now use synchronous CreateProcessW or the unified background worker.

// --- Authoritative Control Loop ---
// RunAutonomousCycle() and CaptureSnapshot() moved verbatim to
// AutonomousEngine::Tick() in autonomous_engine.cpp.

// [FIX] Secondary SEH barrier for the restore thread.
// Plain C-style function with no local C++ objects → __try/__except compiles without C2712.
// If WaitForEventLogRpc races and the exception still fires, this catches it at the thread
// boundary before it becomes unhandled and reaches the crash reporter's termination path.
static void RestorePointThreadSafe()
{
    __try {
        EnsureStartupRestorePoint();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Cannot call Log() here — no C++ objects in __try/__except scope.
        // Log absence of [BACKUP] success message will indicate the exception path was hit.
        OutputDebugStringA("[PMAN] Restore thread: SEH 0x6ba caught at thread boundary.\n");
    }
}

// Background worker queue moved to WorkerQueue (worker_thread.h).
// Owned by PManContext::workerQueue.

// ResponsivenessManager owned by PManContext::Get().subs.responsiveness

// LogViewer moved to log_viewer.cpp / log_viewer.h

// Helper for initial reg read
static DWORD ReadCurrentPrioritySeparation()
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                            0, KEY_QUERY_VALUE, &key);
    if (rc != ERROR_SUCCESS) return 0xFFFFFFFF;
    
    DWORD val = 0;
    DWORD size = sizeof(val);
    rc = RegQueryValueExW(key, L"Win32PrioritySeparation", nullptr, nullptr, reinterpret_cast<BYTE*>(&val), &size);
    RegCloseKey(key);
    
    return (rc == ERROR_SUCCESS) ? val : 0xFFFFFFFF;
}

// [MOVED] Registry Guard implementation moved to restore.cpp

// UpdateTrayTooltip — moved to tray_animator.cpp

// Forward declaration for main program logic
int RunMainProgram(int argc, wchar_t** argv);

// ShowSramNotification — moved to tray_animator.cpp

// --- Custom Tray Animation Helpers ---
// Logic moved to tray_animator.cpp

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Re-add icon if Explorer restarts (TaskbarCreated message)
    if (g_wmTaskbarCreated && uMsg == g_wmTaskbarCreated)
    {
        TrayAnimator::Get().OnTaskbarRestart();
        return 0;
    }

    switch (uMsg)
    {
    case WM_CREATE:
    case WM_TIMER:
    case WM_THEMECHANGED:
    case WM_SETTINGCHANGE:
    case WM_TRAYICON:
    case WM_COMMAND:
    case WM_POWERBROADCAST:
        return TrayManager::HandleMessage(hwnd, uMsg, wParam, lParam);

    case WM_DEVICECHANGE:
        if (wParam == 0x0018 /* DBT_CONFIGCHANGED */)
        {
            Log("[HARDWARE] System configuration changed. Scheduling cache invalidation.");
            g_reloadNow.store(true);
        }
        return TRUE;

    case WM_QUERYENDSESSION:
        return TRUE;

    case WM_ENDSESSION:
        if (wParam == TRUE)
        {
            Log("[LIFECYCLE] Windows restart/shutdown detected. Emergency brain flush.");
            if (PManContext::Get().subs.model)
                PManContext::Get().subs.model->Shutdown();
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 9999);
        TrayAnimator::Get().Shutdown();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}

// Separation of Core Logic for SEH Compatibility
// We rename the original logic to RunPMan so we can wrap it.
static int RunPMan(int argc, wchar_t* argv[])
{
	try {
	
    // [DARK MODE] Initialize Centralized Dark Mode Manager
	DarkMode::Initialize();

    // Initialize Crash Reporter (Black Box & Flight Recorder)
    // Must be initialized before Logger to capture startup failures
    CrashReporter::Initialize();
    
    // Initialize Telemetry-Safe Logger
    InitLogger();

    // Initialize Watchdog Heartbeat (Dedicated Thread)
    PManContext::Get().subs.heartbeat = std::make_unique<HeartbeatSystem>();
    PManContext::Get().subs.heartbeat->Initialize();

    // Lifecycle Management
    std::vector<std::thread> lifecycleThreads;

	// 1. Initialize Global Instance Handle (Required for Tray Icon)
    g_hInst = GetModuleHandle(nullptr);

    // Register system-wide message for Taskbar recreation detection
    g_wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    // 2. Hide Console Window immediately (Restored logic for Console Subsystem)
    // This is required because /SUBSYSTEM:CONSOLE always spawns a window initially.
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != nullptr)
    {
        ShowWindow(consoleWindow, SW_HIDE);
    }

    // 3. argc/argv are provided directly by wmain, no conversion needed.

    // Check for Update Mode (Self-Update)
    if (argc >= 4 && std::wstring(argv[1]) == L"--update") {
        return 0;
    }

    // Check for Guard Mode (Must be before Mutex check)
    if (argc >= 5 && (std::wstring(argv[1]) == L"--guard"))
    {
        DWORD pid = std::wcstoul(argv[2], nullptr, 10);
        // Fixed: Removed redundant low/high split. Expecting direct value.
        DWORD val = std::wcstoul(argv[3], nullptr, 10); 
        std::wstring powerScheme = argv[4];
        
        RunRegistryGuard(pid, val, powerScheme);
        return 0;
    }

    // Fix Silent Install/Uninstall Support
    bool uninstall = false;
    bool silent = false;

	for (int i = 1; i < argc; i++)
    {
        std::wstring arg = argv[i];
		if (arg == L"--help" || arg == L"-h" || arg == L"/?")
        {
            std::wstring version = GetCurrentExeVersion();
            std::wstring msg;
            msg.reserve(512); // Pre-allocate to prevent reallocation fragmentation
            msg += L"Priority Manager (pman) v" + version + L"\n";
            msg += L"by Ian Anthony R. Tancinco\n\n";
            msg += L"Usage: pman.exe [OPTIONS]\n\n";
            msg += L"Options:\n";
            msg += L"  --help, -h, /?      Show this help message\n";
            msg += L"  --uninstall         Stop instances and remove startup task\n";
            msg += L"  --silent, /S         Run operations without message boxes\n";
            msg += L"  --paused             Start in paused mode (Protection Disabled)\n";
            msg += L"  --guard             (Internal) Registry safety guard\n\n";
            msg += L"Automated Windows Priority & Affinity Manager";

            MessageBoxW(nullptr, msg.c_str(), L"Priority Manager - Help", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
		else if (arg == L"--uninstall" || arg == L"/uninstall") uninstall = true;
        else if (arg == L"/S" || arg == L"/s" || arg == L"/silent" || arg == L"-silent" || arg == L"/quiet") silent = true;
        else if (arg == L"--paused") {
            g_userPaused.store(true);
            PManContext::Get().isPaused.store(true);
        }
    }

    if (!uninstall)
    {
        g_hMutex.reset(CreateMutexW(nullptr, TRUE, MUTEX_NAME));
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is already running.", 
                    L"Priority Manager", MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        }
    }
    else
    {
        g_hMutex = nullptr;
    }

    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);

std::wstring taskName = std::filesystem::path(self).stem().wstring();

    if (uninstall)
    {
        Lifecycle::TerminateExistingInstances();

		if (!Lifecycle::IsTaskInstalled(taskName))
        {
            if (!silent)
            {
                MessageBoxW(nullptr, 
                    L"Priority Manager is not currently installed.\nAny running instances have been stopped.", 
                    L"Priority Manager", MB_OK | MB_ICONWARNING);
            }
            g_hMutex.reset();
            return 0;
        }

        Lifecycle::UninstallTask(taskName);

        if (!silent)
        {
            MessageBoxW(nullptr, 
                L"Priority Manager has been successfully uninstalled.\nAny running instance has been stopped and the startup task removed.", 
                L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }

        g_hMutex.reset();
        return 0;
    }

	bool taskExists = Lifecycle::IsTaskInstalled(taskName);

    if (!taskExists)
    {
        // Install in Active mode (false for passive), with /S implied by Lifecycle::InstallTask default logic
        if (Lifecycle::InstallTask(taskName, self, false)) 
        {
             // Wait briefly to ensure task registration propagates
             Sleep(500);
             if (!silent)
                MessageBoxW(nullptr, L"Priority Manager installed successfully!\nIt will now run automatically at logon and is currently active.", L"Priority Manager", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
             if (!silent)
                MessageBoxW(nullptr, L"Failed to create startup task. Please run as Administrator.", L"Priority Manager - Error", MB_OK | MB_ICONWARNING);
             return 1;
        }
    }

    // Console was hidden at startup.
	
	Log("*********************************");
    Log("=== Priority Manager Starting ===");
    Log("All Levels Implemented: Session-Scoped | Cooldown | Registry Guard | Graceful Shutdown | OS Detection | Anti-Interference");
    
	// Initialize Performance Guardian
    if (PManContext::Get().subs.perf) PManContext::Get().subs.perf->Initialize();

    // Initialize Smart Shell Booster
    if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->Initialize();

    // Initialize Input Responsiveness Guard
    if (PManContext::Get().subs.input) PManContext::Get().subs.input->Initialize();

    // Initialize Secure IPC Core
    if (PManContext::Get().subs.ipc) {
        PManContext::Get().subs.ipc->Initialize();
    }

    // Initialize Telemetry Agent (Unblocks Main Loop)
    PManContext::Get().subs.telemetry = std::make_unique<TelemetryAgent>();
    PManContext::Get().subs.telemetry->Initialize();

    // Initialize Policy Optimizer
    PManContext::Get().subs.optimizer = std::make_unique<PolicyOptimizer>();
    PManContext::Get().subs.optimizer->Initialize();

    // Initialize Policy Contract (Boundary Formalization)
    PManContext::Get().subs.policy = std::make_unique<PolicyGuard>();
    // Note: If policy.json is missing, it fails open (safe defaults) or logs warning. 
    // It is read-only and will never be created by the system.
    if (PManContext::Get().subs.policy->Load(GetLogPath() / L"policy.json")) {
        Log("[INIT] Policy Contract loaded. Hash: " + PManContext::Get().subs.policy->GetHash());
        // [FIX] Apply Budget Limit from Policy
        if (PManContext::Get().subs.budget) {
            PManContext::Get().subs.budget->SetMax(PManContext::Get().subs.policy->GetLimits().maxAuthorityBudget);
        }
    } else {
        Log("[INIT] WARNING: policy.json missing or invalid. Using hardcoded safe defaults.");
        Log("[INIT] No policy.json found. Authority is DISABLED. To enable autonomy, provide a valid policy.json.");
    }

    // Initialize Autonomous Engine (Engine Orchestrator — Ring 2)
    // Must be initialized after: telemetry, optimizer, policy, budget, governor,
    // evaluator, arbiter, shadow, sandbox, intent, guard, confidence, ledger, provenance.
    if (PManContext::Get().subs.engine) {
        PManContext::Get().subs.engine->Init();
    }

	// Initialize Smart Memory Optimizer
    if (PManContext::Get().subs.mem) PManContext::Get().subs.mem->Initialize();

	// Initialize Service Watcher
    ServiceWatcher::Initialize();

    // Initialize SRAM (System Responsiveness Awareness Module)
    // Must be initialized before subsystems that depend on LagState
    SramEngine::Get().Initialize();

    DetectOSCapabilities();
    // [FIX] Use RestorePointThreadSafe: plain C function with __try/__except at thread entry.
    // No C++ objects in its scope, so MSVC C2712 does not apply.
    std::thread restoreThread(RestorePointThreadSafe);
    lifecycleThreads.push_back(std::move(restoreThread));
    
    DetectHybridCoreSupport();

    // Safety check: Restore services if they were left suspended from a crash
    if (g_caps.hasAdminRights && PManContext::Get().subs.serviceMgr && PManContext::Get().subs.serviceMgr->Initialize())
    {
		/*
        PManContext::Get().subs.serviceMgr->AddService(L"wuauserv", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
        PManContext::Get().subs.serviceMgr->AddService(L"BITS", 
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE | SERVICE_STOP | SERVICE_START);
        */

        // Check if services are suspended (shouldn't be at startup)
        ScHandle scManager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (scManager)
        {
            auto CheckAndRecover = [&](const wchar_t* name) {
                ScHandle hSvc(OpenServiceW(scManager.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START));
                if (hSvc)
                {
                    // 1. Check if DISABLED first
            DWORD bytesNeeded = 0;
            // Fix C6031: Check return value (expect failure with buffer size)
            if (!QueryServiceConfigW(hSvc.get(), nullptr, 0, &bytesNeeded) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<BYTE> buffer(bytesNeeded);
                        LPQUERY_SERVICE_CONFIGW config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
                        if (QueryServiceConfigW(hSvc.get(), config, bytesNeeded, &bytesNeeded)) {
                            if (config->dwStartType == SERVICE_DISABLED) {
                                return; // Ignore disabled services
                            }
                        }
                    }

                    // 2. Check Status and Recover
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hSvc.get(), &status))
                    {
                        if (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_PAUSED)
                        {
                            Log(std::string("[STARTUP] WARNING: ") + WideToUtf8(name) + " was stopped/paused - attempting recovery");
                            StartServiceW(hSvc.get(), 0, nullptr);
                        }
                    }
                }
            };

            CheckAndRecover(L"wuauserv");
            CheckAndRecover(L"BITS");
        }
    }

    LoadConfig();
    
    g_hIocp.reset(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!g_hIocp)
    {
        Log("Failed to create IOCP: " + std::to_string(GetLastError()));
        return 1;
    }

    g_hShutdownEvent.reset(CreateEventW(nullptr, TRUE, FALSE, SHUTDOWN_EVENT_NAME));
    if (!g_hShutdownEvent)
    {
        Log("Failed to create shutdown event: " + std::to_string(GetLastError()));
    }
    
    // Helper to pin thread to Efficiency cores (ARM64/Hybrid safe)
    auto PinBackgroundThread = [](std::thread& t) {
        if (!g_eCoreSets.empty()) {
            // Pin to first two Efficiency cores
            DWORD_PTR mask = 0;
            if (g_eCoreSets.size() >= 1) mask |= (1ULL << g_eCoreSets[0]);
            if (g_eCoreSets.size() >= 2) mask |= (1ULL << g_eCoreSets[1]);
            SetThreadAffinityMask(t.native_handle(), mask);
        }
        else if (g_physicalCoreCount >= 4) {
            // Legacy Fallback: Use last 2 physical cores
            DWORD_PTR affinityMask = (1ULL << (g_physicalCoreCount - 1)) | (1ULL << (g_physicalCoreCount - 2));
            SetThreadAffinityMask(t.native_handle(), affinityMask);
        }
        // Always lower priority to prevent interference
        SetThreadPriority(t.native_handle(), THREAD_PRIORITY_LOWEST);
    };
    
    std::thread configThread(IocpConfigWatcher);
    PinBackgroundThread(configThread);

    // Initialize unified background worker
    PManContext::Get().workerQueue.Start();
    // Pin background worker thread to E-Cores/low-priority physical cores
    // (mirrors PinBackgroundThread used for other threads)
    if (!g_eCoreSets.empty()) {
        DWORD_PTR mask = 0;
        if (g_eCoreSets.size() >= 1) mask |= (1ULL << g_eCoreSets[0]);
        if (g_eCoreSets.size() >= 2) mask |= (1ULL << g_eCoreSets[1]);
        SetThreadAffinityMask(PManContext::Get().workerQueue.NativeHandle(), mask);
    } else if (g_physicalCoreCount >= 4) {
        DWORD_PTR affinityMask = (1ULL << (g_physicalCoreCount - 1)) | (1ULL << (g_physicalCoreCount - 2));
        SetThreadAffinityMask(PManContext::Get().workerQueue.NativeHandle(), affinityMask);
    }
    SetThreadPriority(PManContext::Get().workerQueue.NativeHandle(), THREAD_PRIORITY_LOWEST);
    Sleep(100); // [POLISH] Stagger start
    
    std::thread etwThread;
    if (g_caps.canUseEtw)
    {
        etwThread = std::thread(EtwThread);
        PinBackgroundThread(etwThread);
        Sleep(100); // [POLISH] Stagger start
    }
    
    std::thread watchdogThread(AntiInterferenceWatchdog);
    PinBackgroundThread(watchdogThread);
    Sleep(100); // [POLISH] Stagger start

    // MemoryOptimizer background thread removed.
    // The Optimizer now runs synchronously as a pure Sensor during AutonomousEngine::Tick().

    // FIX: Check return value (C6031)
    HRESULT hrInit = CoInitialize(nullptr);
    if (FAILED(hrInit)) {
        Log("[INIT] CoInitialize failed: " + std::to_string(hrInit));
        PManContext::Get().fault.comFailure.store(true);
    }

    // Network Intelligence
    g_networkMonitor.Initialize();
    
    HWINEVENTHOOK hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
                                         nullptr, WinEventProc, 0, 0,
                                         WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hook) 
    { 
        Log("SetWinEventHook failed: " + std::to_string(GetLastError()));
    }
    
	WNDCLASSW wc{}; 
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = L"PMHidden";
    wc.hInstance = g_hInst; // FIX: Use global instance handle
    RegisterClassW(&wc);
    
	// Parent must be nullptr (Top-level) for Tray Icon to receive events reliably
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"PriorityManagerTray", 0, 0, 0, 0, 0, 
                              nullptr, nullptr, g_hInst, nullptr); // FIX: Use global instance handle
    RegisterPowerNotifications(hwnd);
    
    // Register for Raw Input to track user activity (Keyboard & Mouse) for Explorer Booster
    RAWINPUTDEVICE Rid[2];
    // Keyboard
    Rid[0].usUsagePage = 0x01; 
    Rid[0].usUsage = 0x06; 
    Rid[0].dwFlags = RIDEV_INPUTSINK;   
    Rid[0].hwndTarget = hwnd;
    // Mouse
    Rid[1].usUsagePage = 0x01; 
    Rid[1].usUsage = 0x02; 
    Rid[1].dwFlags = RIDEV_INPUTSINK; 
    Rid[1].hwndTarget = hwnd;

    if (!RegisterRawInputDevices(Rid, 2, sizeof(Rid[0]))) {
        Log("[INIT] Raw Input registration failed: " + std::to_string(GetLastError()));
    } else {
        Log("[INIT] Raw Input registered for idle detection");
    }

    Log("Background mode ready - monitoring foreground applications");
    
    DWORD currentSetting = ReadCurrentPrioritySeparation();
    if (currentSetting != 0xFFFFFFFF)
    {
        Log("Current system setting: " + GetModeDescription(currentSetting));
        g_originalRegistryValue = currentSetting;
        g_cachedRegistryValue.store(currentSetting);
        
        // Launch Crash-Proof Guard
        if (g_restoreOnExit.load())
        {
            // Capture handle for lifecycle management
            HANDLE hGuard = LaunchRegistryGuard(currentSetting);
            g_hGuardProcess.reset(hGuard);
            
            if (!g_hGuardProcess || g_hGuardProcess.get() == INVALID_HANDLE_VALUE) {
                Log("[CRITICAL] Failed to launch Registry Guard. Crash protection disabled.");
                g_hGuardProcess.reset();
            }
        }
    }
    else
    {
        Log("WARNING: Unable to read current registry setting");
	}
    
	MSG msg;
    // FIX: Use 64-bit time tracking to prevent overflow issues (C28159)
    static uint64_t g_lastExplorerPollMs = 0;

    while (g_running)
    {
        if (CheckForShutdownSignal())
        {
            PerformGracefulShutdown();
            break;
        }
        
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                g_running = false;
                break;
            }
            
            if (msg.message == WM_INPUT) 
            {
                // Signal user activity to Smart Shell Booster
                if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->OnUserActivity();
                
                // Input Responsiveness Guard
                // Monitor latency and boost foreground threads
                if (PManContext::Get().subs.input) PManContext::Get().subs.input->OnInput(msg.time);
                
                // [FIX] Single dispatch: call DefWindowProc directly and skip DispatchMessage
                // to prevent WM_INPUT from being routed through WindowProc->DefWindowProcW a second time.
                DefWindowProc(msg.hwnd, msg.message, msg.wParam, msg.lParam);
                continue;
            }
            
            TranslateMessage(&msg); // [FIX] Convert keystrokes to characters for GUI input
            DispatchMessage(&msg);
        }
        
		if (g_reloadNow.exchange(false))
        {
            // [PERF FIX] Offload to persistent worker thread
            PManContext::Get().workerQueue.Push([]() {
                Sleep(250);
                // [CACHE] Atomic destruction on Config Reload
                g_sessionCache.store(nullptr, std::memory_order_release);
                Sleep(250);
                LoadConfig();

                // [FIX] Reload Policy and Sync Budget
                if (PManContext::Get().subs.policy) {
                    PManContext::Get().subs.policy->Load(GetLogPath() / L"policy.json");
                    
                    // [SYNC] Push new thresholds to Arbiter immediately
                    if (PManContext::Get().subs.arbiter) {
                         auto& limits = PManContext::Get().subs.policy->GetLimits();
                         PManContext::Get().subs.arbiter->SetConfidenceThresholds(
                            limits.minConfidence.cpuVariance,
                            limits.minConfidence.thermalVariance,
                            limits.minConfidence.latencyVariance
                         );
                    }
                }
                
                // [RECOVERY] Sync Budget Cap (But do NOT reset usage)
                // Changing config.ini (games/apps) should not grant budget amnesty.
                // Only a Policy change (maxAuthorityBudget) should affect the ceiling.
                if (PManContext::Get().subs.budget) {
                    if (PManContext::Get().subs.policy) {
                        PManContext::Get().subs.budget->SetMax(PManContext::Get().subs.policy->GetLimits().maxAuthorityBudget);
                    }
                    // REMOVED: PManContext::Get().subs.budget->ResetByExternalSignal();
                }
            });
        }

        // Safety check: ensure services are not left suspended
        CheckAndReleaseSessionLock();

        // Handle Resume Stabilization (Non-blocking)
        if (g_resumeStabilizationTime > 0) {
             if (GetTickCount64() >= g_resumeStabilizationTime) {
                 g_isSuspended.store(false);
                 g_resumeStabilizationTime = 0;
                 Log("System stabilized - resuming operations");
             }
        }

        // GUI Rendering Integration
        // [FIX] Protection: Stop rendering if system is suspended/stabilizing to prevent D3D crash
        if (GuiManager::IsWindowOpen() && !g_isSuspended.load()) {
            GuiManager::RenderFrame();
        }

        // Wait for messages with timeout - efficient polling that doesn't spin CPU
        // Use MsgWaitForMultipleObjects to stay responsive to inputs/shutdown while waiting
        // Reduced timeout to 16ms (~60 FPS) only when GUI is open to ensure smooth rendering
        DWORD waitTimeout = GuiManager::IsWindowOpen() ? 16 : 100;
        
        // Fix: Use local handle for array pointer requirement
        HANDLE hShutdown = g_hShutdownEvent.get();
        DWORD waitResult = MsgWaitForMultipleObjects(1, &hShutdown, FALSE, waitTimeout, QS_ALLINPUT);

        // [SAFETY] Fix C4189 & Prevent CPU spin if API fails
        if (waitResult == WAIT_FAILED) {
            Sleep(100); 
            continue;
        }

        // [OPTIMIZATION] If shutdown event signaled, skip tick logic to exit faster
        if (waitResult == WAIT_OBJECT_0) {
            continue;
        }
        
        // [FIX] MOVED OUTSIDE: Check tick timers regardless of input state
        // This ensures scanning happens even if the user is moving the mouse
        {
            // Calculate adaptive polling interval based on idle state
            // FIX: Use GetTickCount64 (C28159)
            uint64_t now = GetTickCount64();
            uint64_t idleDurationMs = PManContext::Get().subs.explorer ? (now - PManContext::Get().subs.explorer->GetLastUserActivity()) : 0;
            uint32_t thresholdMs = PManContext::Get().subs.explorer ? PManContext::Get().subs.explorer->GetIdleThreshold() : 300000;
            
            // Adaptive poll rate: poll faster when approaching idle threshold (within 5s)
            bool approachingIdle = (idleDurationMs > 0 && idleDurationMs < thresholdMs && 
                                   idleDurationMs > (thresholdMs - 5000));
            uint32_t pollIntervalMs = approachingIdle ? 250 : 2000;

            // Rate limit the tick calls to prevent CPU spinning
            if ((now - g_lastExplorerPollMs) >= pollIntervalMs) {
                
                // FIX: Offload to persistent worker thread to protect Keyboard Hook
                PManContext::Get().workerQueue.Push([]{
					// Moved ExplorerBooster to background thread to prevent blocking the Keyboard Hook
					if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->OnTick();

				// Authoritative Control Loop
                if (PManContext::Get().subs.engine) {
                    PManContext::Get().subs.engine->Tick();
                }

                // Periodic Policy Optimization (Slow Loop)
                static uint64_t lastOpt = 0;
                if (GetTickCount64() - lastOpt > 60000) { // Every 1 minute
                    if (auto& opt = PManContext::Get().subs.optimizer) {
                        PolicyParameters newParams = opt->Optimize();
                        if (auto& gov = PManContext::Get().subs.governor) {
                            gov->UpdatePolicy(newParams);
                        }
                    }
                    lastOpt = GetTickCount64();
                }

                // [FIX] Periodic Brain Save (Every 15 minutes)
                static uint64_t lastBrainSave = GetTickCount64();
                if (GetTickCount64() - lastBrainSave > 900000) {
                    if (auto& model = PManContext::Get().subs.model) {
                        model->Shutdown(); // Writes m_stats to brain.bin
                    }
                    lastBrainSave = GetTickCount64();
                }

					// Legacy/Advisory Updates (Data Collection Only)
					if (PManContext::Get().subs.perf) PManContext::Get().subs.perf->OnPerformanceTick();
                    
                    // [FIX] Move heavy window checks to background to prevent main thread stutter
                    if (PManContext::Get().subs.responsiveness) PManContext::Get().subs.responsiveness->Update();
                });
                
                // Run Service Watcher
                ServiceWatcher::OnTick();

                // SRAM UI Updates
                static LagState lastKnownState = LagState::SNAPPY;
                LagState currentState = SramEngine::Get().GetStatus().state;
                
                if (currentState != lastKnownState) {
                    UpdateTrayTooltip(); // Refresh tooltip text
                    ShowSramNotification(currentState); // Show balloon if critical
                    lastKnownState = currentState;
                }
                
                g_lastExplorerPollMs = now;
            }
        }
    }
    
	if (hook) UnhookWinEvent(hook);
    
    // FIX: Explicitly unregister raw input devices (Renamed to RidCleanup to avoid redefinition error)
    RAWINPUTDEVICE RidCleanup[2] = {};
    RidCleanup[0].usUsagePage = 0x01; RidCleanup[0].usUsage = 0x06; RidCleanup[0].dwFlags = RIDEV_REMOVE; RidCleanup[0].hwndTarget = nullptr;
    RidCleanup[1].usUsagePage = 0x01; RidCleanup[1].usUsage = 0x02; RidCleanup[1].dwFlags = RIDEV_REMOVE; RidCleanup[1].hwndTarget = nullptr;
    RegisterRawInputDevices(RidCleanup, 2, sizeof(RAWINPUTDEVICE));

    // [FIX] Stop background worker BEFORE destroying UI/Subsystems to prevent deadlocks/use-after-free
    PManContext::Get().workerQueue.Stop();

    // Shutdown Autonomous Engine (must be after workerQueue.Stop — no Tick() can fire after this)
    if (PManContext::Get().subs.engine) {
        PManContext::Get().subs.engine->Shutdown();
    }

    GuiManager::Shutdown(); // Cleanup DX11/ImGui resources

	UnregisterPowerNotifications();
    if (hwnd) DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, g_hInst); // FIX: Use global instance handle
    
    CoUninitialize();
    
	g_running = false;
    g_networkMonitor.Stop(); // Stop Monitor
    if (PManContext::Get().subs.telemetry) PManContext::Get().subs.telemetry->Shutdown();
    if (PManContext::Get().subs.heartbeat) PManContext::Get().subs.heartbeat->Shutdown();
    if (PManContext::Get().subs.explorer) PManContext::Get().subs.explorer->Shutdown();
    if (PManContext::Get().subs.input) PManContext::Get().subs.input->Shutdown();
    if (PManContext::Get().subs.mem) PManContext::Get().subs.mem->Shutdown();
    SramEngine::Get().Shutdown();

    // [FIX] Save Brain and Stop Executor
    // This ensures brain.bin is written to disk
    if (PManContext::Get().subs.executor) {
        PManContext::Get().subs.executor->Shutdown();
    }
    if (PManContext::Get().subs.optimizer) {
        PManContext::Get().subs.optimizer->Shutdown();
    }
    // [FIX] Save the Brain before exiting
    if (PManContext::Get().subs.model) {
        PManContext::Get().subs.model->Shutdown();
    }
	
    // Signal threads to wake up/stop
    if (g_hShutdownEvent) SetEvent(g_hShutdownEvent.get()); // Wakes Watchdog immediately
    StopEtwSession(); // Unblocks EtwThread (ProcessTrace returns)
    PostShutdown(); // Wakes IocpConfigWatcher
    
    // Background worker stopped earlier to ensure thread safety

    if (configThread.joinable()) configThread.join();
    if (etwThread.joinable()) etwThread.join();
    if (watchdogThread.joinable()) watchdogThread.join();
    
    // Join managed lifecycle threads
    for (auto& t : lifecycleThreads) {
        if (t.joinable()) t.join();
    }
    
    // RAII Cleanup handled by PManContext destructor
    // Explicitly release mutex ownership before closing handle
    if (g_hMutex) {
        ReleaseMutex(g_hMutex.get());
        g_hMutex.reset();
    }
    
    g_hIocp.reset();
    g_hShutdownEvent.reset();
    
    // Safety cleanup for Power Scheme
    if (g_pSleepScheme) {
        PowerSetActiveScheme(NULL, g_pSleepScheme.get());
        g_pSleepScheme.reset(); // Auto-calls LocalFree via Deleter
    }

    // Terminate Guard Process on graceful shutdown to prevent false positives
    if (g_hGuardProcess) {
        TerminateProcess(g_hGuardProcess.get(), 0);
        g_hGuardProcess.reset();
        Log("[GUARD] Watchdog process terminated gracefully.");
    }

    // [FIX] Manual Restoration on Graceful Exit
    if (g_restoreOnExit.load() && g_originalRegistryValue != 0xFFFFFFFF) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\PriorityControl", 
                         0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"Win32PrioritySeparation", 0, REG_DWORD, 
                          reinterpret_cast<const BYTE*>(&g_originalRegistryValue), sizeof(DWORD));
            RegCloseKey(hKey);
            Log("[SHUTDOWN] Restored original Priority Separation: " + std::to_string(g_originalRegistryValue));
        }
    }

    Log("=== Priority Manager Stopped ===");
    
    // Flush logs to disk before exit
    ShutdownLogger();

    return 0;

    } catch (const std::exception& e) {
        // Top-level crash boundary
        std::string msg = "[CRITICAL] Unhandled exception in main: ";
        msg += e.what();
        
        // Try logging to disk
        try {
            Log(msg);
            ShutdownLogger(); // Force flush
        } catch (...) {
            // Ignore secondary failures during crash handling
        }

        // Deterministic failure - visible to OS/User
        MessageBoxA(nullptr, msg.c_str(), "Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;

    } catch (...) {
        // Catch non-standard exceptions
        try {
            Log("[CRITICAL] Unknown non-standard exception caught in main.");
            ShutdownLogger();
        } catch (...) {
            // Ignore secondary failures
        }

        MessageBoxW(nullptr, L"Unknown fatal error occurred.", L"Priority Manager - Fatal Error", MB_OK | MB_ICONERROR);
        return -1;
    }
}

// SEH Entry Point
// This wrapper catches hardware faults (Stack Overflow, Access Violation)
// that standard C++ try/catch blocks cannot handle.
int wmain(int argc, wchar_t* argv[])
{
    // Initialize Crash Reporter immediately
    CrashReporter::Initialize();

    __try {
        // [FIX] RunPMan is a static function in this file, not a member of GuiManager
        return RunPMan(argc, argv);
    }
    __except (CrashReporter::SehFilter(GetExceptionInformation())) {
        // The filter writes the dump and terminates the process.
        // We return -1 just to satisfy the signature if termination is delayed.
        return -1;
    }
}
