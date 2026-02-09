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

#include "gui_manager.h"
#include "static_tweaks.h"
#include "config.h"
#include "logger.h"
#include "utils.h" // For GetCurrentExeVersion
#include "context.h"
#include "policy_contract.h"
#include "external_verdict.h"
#include "globals.h"
#include "editor_manager.h"
#include "constants.h"

#include <d3d11.h>
#include <dwmapi.h> // Required for transparency
#include <tchar.h>
#include <string>
#include <filesystem>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace GuiManager {

    // ============================================================================================
    // Global State
    // ============================================================================================
    static ID3D11Device*           g_pd3dDevice = nullptr;
    static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
    static IDXGISwapChain*         g_pSwapChain = nullptr;
    static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

    static HWND g_hwnd = nullptr;
    static bool g_isInitialized = false;
    static bool g_isOpen = false;
    
    enum class GuiMode { TuneUp, About, Help, LogViewer, Config };
    static GuiMode g_activeMode = GuiMode::TuneUp;
    
    // [PATCH] Tab Navigation Request
    static std::string g_requestedTab = "";

    void OpenPolicyTab() {
        ShowConfigWindow();
        g_requestedTab = "Policy";
    }

    // Config Window State
    struct ConfigState {
        // Tab 1: Global
        bool ignoreNonInteractive = true;
        bool restoreOnExit = true;
        bool lockPolicy = false;
        bool suspendUpdates = false;
        bool idleRevert = true;
        int idleTimeoutSec = 300;
        bool recovery = true;
        bool recoveryPrompt = true;
        char iconTheme[64] = "Default";

        // Tab 2: Explorer
        bool expEnabled = true;
        int expIdleThresholdSec = 15;
        bool boostDwm = true;
        bool boostIo = false;
        bool disableEco = true;
        bool preventPaging = true;
        int scanIntervalSec = 5;
        bool debugLog = false;
        
        // Tab Debug: Faults
        bool faultLedger = false;
        bool faultBudget = false;
        bool faultSandbox = false;
        bool faultIntent = false;
        bool faultConfidence = false;

        // Tab 3: Policy
        int maxBudget = 100;
        float cpuVar = 0.01f;
        float latVar = 0.02f;
        bool allowThrottleMild = true;
        bool allowThrottleAggressive = true;
        bool allowOptimize = true;
        bool allowSuspend = true;
        bool allowPressure = true;
        bool allowMaintain = true;

        // Tab 4: Verdict
        int verdictIdx = 0; // 0=ALLOW, 1=DENY, 2=CONSTRAIN
        int durationHours = 24;
    };
    static ConfigState g_configState;

    // Log Viewer State
    static std::string g_logBuffer;
    static bool g_logAutoScroll = true;
    static uint64_t g_lastLogCheck = 0;
    static std::streampos g_logLastPos = 0;
	static size_t g_logPrevSize = 0;
    static float g_logMaxWidth = 0.0f;
    static int g_logLineCount = 0;

    static void UpdateLogContent() {
        uint64_t now = GetTickCount64();
        if (now - g_lastLogCheck < 500) return; // Check every 500ms
        g_lastLogCheck = now;

        std::filesystem::path logPath = GetLogPath() / L"log.txt";
        HANDLE hFile = CreateFileW(logPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE) return;

        LARGE_INTEGER size;
        GetFileSizeEx(hFile, &size);

        if (size.QuadPart < g_logLastPos) {
            g_logLastPos = 0; // File was truncated/reset
            g_logBuffer.clear();
            g_logMaxWidth = 0.0f;
        }

        if (size.QuadPart > g_logLastPos) {
            DWORD bytesToRead = (DWORD)(size.QuadPart - g_logLastPos);
            // Limit read to last 64KB if opened for the first time
            if (bytesToRead > 65536 && g_logLastPos == 0) {
                g_logLastPos = size.QuadPart - 65536;
                bytesToRead = 65536;
            }

            std::vector<char> buffer(bytesToRead + 1);
            LARGE_INTEGER move; move.QuadPart = g_logLastPos;
            SetFilePointerEx(hFile, move, nullptr, FILE_BEGIN);
            
            DWORD bytesRead = 0;
            if (ReadFile(hFile, buffer.data(), bytesToRead, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                g_logBuffer.append(buffer.data());
                g_logLastPos += bytesRead;

                }
        }
        CloseHandle(hFile);
    }

    static WNDCLASSEXW g_wc = {
        sizeof(WNDCLASSEXW),
        CS_CLASSDC,
        nullptr,
        0L, 0L,
        GetModuleHandle(nullptr),
        nullptr, nullptr, nullptr, nullptr,
        L"PManGuiClass",
        nullptr
    };

    static TweakConfig g_config;

    // Fonts
    static ImFont* g_pFontRegular = nullptr;
    static ImFont* g_pFontTitle   = nullptr;

    // ============================================================================================
    // Forward declarations
    // ============================================================================================
    bool    CreateDeviceD3D(HWND hWnd);
    void    CleanupDeviceD3D();
    void    CreateRenderTarget();
    void    CleanupRenderTarget();
	void    RecoverFromDeviceLoss();
    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // ============================================================================================
    // Styling
    // ============================================================================================
    void ApplyModern3DStyle() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        style.WindowRounding = 12.0f;
        style.ChildRounding = 8.0f;
        style.FrameRounding = 6.0f;
        style.TabRounding = 6.0f;

        style.WindowPadding = ImVec2(16, 16);
        style.FramePadding = ImVec2(12, 8);
        style.ItemSpacing = ImVec2(12, 8);

        colors[ImGuiCol_WindowBg] = ImVec4(0.09f, 0.09f, 0.11f, 1.00f);
        colors[ImGuiCol_ChildBg]  = ImVec4(0.12f, 0.12f, 0.15f, 1.00f);
        colors[ImGuiCol_Text]     = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
        colors[ImGuiCol_Button]   = ImVec4(0.20f, 0.25f, 0.35f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.30f, 0.38f, 0.50f, 1.00f);
        colors[ImGuiCol_ButtonActive]  = ImVec4(0.40f, 0.50f, 0.65f, 1.00f);

        // [FIX] Tab Highlighting
        colors[ImGuiCol_Tab]                = ImVec4(0.15f, 0.20f, 0.30f, 1.00f);
        colors[ImGuiCol_TabHovered]         = ImVec4(0.35f, 0.50f, 0.80f, 0.80f);
        colors[ImGuiCol_TabActive]          = ImVec4(0.28f, 0.45f, 0.75f, 1.00f);
        colors[ImGuiCol_TabUnfocused]       = ImVec4(0.10f, 0.12f, 0.18f, 1.00f);
        colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.18f, 0.28f, 0.50f, 1.00f);
    }

    // ============================================================================================
    // Helpers
    // ============================================================================================
    static void HelpMarker(const char* desc) {
        ImGui::SameLine();
        ImGui::TextDisabled("(?)");
        if (ImGui::BeginItemTooltip()) {
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::TextUnformatted(desc);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }

    void BeginCard(const char* id, ImVec4 color) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, color);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::BeginChild(id, ImVec2(0, 0), true);
    }

    void EndCard() {
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
    }

    // ============================================================================================
    // Init / Shutdown
    // ============================================================================================
    void Init() {
        if (g_isInitialized) return;

        g_wc.lpfnWndProc = WndProc;
        RegisterClassExW(&g_wc);

        int w = 600, h = 520;
        int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

        g_hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            g_wc.lpszClassName,
            L"PMan - System TuneUp",
            WS_POPUP,
            x, y, w, h,
            nullptr, nullptr,
            g_wc.hInstance,
            nullptr
        );

        // [FIX] Enable transparent framebuffer for rounded corners
        MARGINS margins = {-1};
        DwmExtendFrameIntoClientArea(g_hwnd, &margins);

        if (!CreateDeviceD3D(g_hwnd)) {
            CleanupDeviceD3D();
            return;
        }

        ShowWindow(g_hwnd, SW_SHOW);
        UpdateWindow(g_hwnd);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGui::GetIO().IniFilename = nullptr;

        ApplyModern3DStyle();

        // Load System Fonts (Segoe UI)
        char winFolder[MAX_PATH];
        if (GetWindowsDirectoryA(winFolder, MAX_PATH)) {
            std::string fontPath = std::string(winFolder) + "\\Fonts\\segoeui.ttf";
            std::string boldPath = std::string(winFolder) + "\\Fonts\\segoeb.ttf"; // Segoe UI Bold

            ImGuiIO& io = ImGui::GetIO();
            
            // Main Font (18px)
            if (std::filesystem::exists(fontPath)) {
                g_pFontRegular = io.Fonts->AddFontFromFileTTF(fontPath.c_str(), 18.0f);
            }
            
            // Title Font (32px)
            if (std::filesystem::exists(boldPath)) {
                g_pFontTitle = io.Fonts->AddFontFromFileTTF(boldPath.c_str(), 32.0f);
            }
        }

        ImGui_ImplWin32_Init(g_hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        LoadTweakPreferences(g_config);
        g_isInitialized = true;
    }

    void ShowTuneUpWindow() {
        ShowConfigWindow();
    }

    void ShowAboutWindow() {
        if (!g_isInitialized) Init();
        g_activeMode = GuiMode::About;
        g_isOpen = true;
        ShowWindow(g_hwnd, SW_SHOW);
        SetForegroundWindow(g_hwnd);
    }

    void ShowHelpWindow() {
        if (!g_isInitialized) Init();
        g_activeMode = GuiMode::Help;
        g_isOpen = true;
        ShowWindow(g_hwnd, SW_SHOW);
        SetForegroundWindow(g_hwnd);
    }

	void ShowLogWindow() {
        if (!g_isInitialized) Init();
        g_activeMode = GuiMode::LogViewer;
        g_isOpen = true;
        // [FIX] Force write buffered logs to disk so the viewer can read them
        FlushLogger();
        // Reset state on open
        g_logLastPos = 0; 
        g_logBuffer.clear();
        UpdateLogContent(); // Immediate read
        ShowWindow(g_hwnd, SW_SHOW);
        SetForegroundWindow(g_hwnd);
    }

    void ShowConfigWindow() {
        if (!g_isInitialized) Init();
        g_activeMode = GuiMode::Config;
        
        // Populate Global State
        g_configState.ignoreNonInteractive = g_ignoreNonInteractive.load();
        g_configState.restoreOnExit = g_restoreOnExit.load();
        g_configState.lockPolicy = g_lockPolicy.load();
        g_configState.suspendUpdates = g_suspendUpdatesDuringGames.load();
        g_configState.idleRevert = g_idleRevertEnabled.load();
        g_configState.idleTimeoutSec = g_idleTimeoutMs.load() / 1000;
        g_configState.recovery = g_responsivenessRecoveryEnabled.load();
        g_configState.recoveryPrompt = g_recoveryPromptEnabled.load();
        
        {
            std::shared_lock lg(g_setMtx);
            std::string theme = WideToUtf8(g_iconTheme.c_str());
            strncpy_s(g_configState.iconTheme, theme.c_str(), 63);
        }

        // Populate Explorer State
        ExplorerConfig ec = GetExplorerConfigShadow();
        g_configState.expEnabled = ec.enabled;
        g_configState.expIdleThresholdSec = ec.idleThresholdMs / 1000;
        g_configState.boostDwm = ec.boostDwm;
        g_configState.boostIo = ec.boostIoPriority;
        g_configState.disableEco = ec.disablePowerThrottling;
        g_configState.preventPaging = ec.preventShellPaging;
        g_configState.scanIntervalSec = ec.scanIntervalMs / 1000;
        g_configState.debugLog = ec.debugLogging;

        // Populate Fault State
        auto& f = PManContext::Get().fault;
        g_configState.faultLedger = f.ledgerWriteFail;
        g_configState.faultBudget = f.budgetCorruption;
        g_configState.faultSandbox = f.sandboxError;
        g_configState.faultIntent = f.intentInvalid;
        g_configState.faultConfidence = f.confidenceInvalid;

        if (auto& pol = PManContext::Get().subs.policy) {
            const auto& lim = pol->GetLimits();
            g_configState.maxBudget = lim.maxAuthorityBudget;
            g_configState.cpuVar = (float)lim.minConfidence.cpuVariance;
            g_configState.latVar = (float)lim.minConfidence.latencyVariance;
            
            g_configState.allowThrottleMild = lim.allowedActions.count((int)BrainAction::Throttle_Mild);
            g_configState.allowThrottleAggressive = lim.allowedActions.count((int)BrainAction::Throttle_Aggressive);
            g_configState.allowOptimize = lim.allowedActions.count((int)BrainAction::Optimize_Memory);
            g_configState.allowSuspend = lim.allowedActions.count((int)BrainAction::Suspend_Services);
            g_configState.allowPressure = lim.allowedActions.count((int)BrainAction::Release_Pressure);
            g_configState.allowMaintain = lim.allowedActions.count((int)BrainAction::Maintain);
        }

        g_isOpen = true;
        ShowWindow(g_hwnd, SW_SHOW);
        SetForegroundWindow(g_hwnd);
    }
	
    bool IsWindowOpen() {
        return g_isOpen;
    }

    void Shutdown() {
        if (!g_isInitialized) return;

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        CleanupDeviceD3D();
        DestroyWindow(g_hwnd);
        UnregisterClassW(g_wc.lpszClassName, g_wc.hInstance);

        g_isInitialized = false;
        g_isOpen = false;
        g_hwnd = nullptr;
    }

    // ============================================================================================
    // Render
    // ============================================================================================
    void RenderFrame() {
        if (!g_isOpen) return;

        MSG msg;
        while (PeekMessage(&msg, g_hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin(
            "PManMain",
            nullptr,
            ImGuiWindowFlags_NoDecoration |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoSavedSettings
        );

        // Apply Regular Font Global
        if (g_pFontRegular) ImGui::PushFont(g_pFontRegular);

        // ----------------------------------------------------------------------------------------
        // DRAGGABLE HEADER AREA
        // ----------------------------------------------------------------------------------------
        const float headerHeight = 70.0f;
        ImGui::InvisibleButton("##drag_header", ImVec2(ImGui::GetWindowWidth(), headerHeight));

        if (ImGui::IsItemActive()) {
            POINT p;
            GetCursorPos(&p);
            SetWindowPos(
                g_hwnd,
                nullptr,
                p.x - (int)(ImGui::GetWindowWidth() * 0.5f),
                p.y - (int)(headerHeight * 0.5f),
                0, 0,
                SWP_NOSIZE | SWP_NOZORDER
            );
        }

        // ----------------------------------------------------------------------------------------
        // CENTERED TITLE
        // ----------------------------------------------------------------------------------------
        const char* title = "PMAN TWEAKS";
        if (g_activeMode == GuiMode::About) title = "ABOUT";
        else if (g_activeMode == GuiMode::Help) title = "HELP";
        else if (g_activeMode == GuiMode::LogViewer) title = "PMAN LIVE LOG";
        else if (g_activeMode == GuiMode::Config) title = "NEURAL CENTER";

        // Use loaded Title Font if available, otherwise fallback to scaling
        if (g_pFontTitle) ImGui::PushFont(g_pFontTitle);
        else ImGui::SetWindowFontScale(2.2f);

        ImVec2 textSize = ImGui::CalcTextSize(title);
        float centerX = (ImGui::GetWindowWidth() - textSize.x) * 0.5f;
        ImGui::SetCursorPos(ImVec2(centerX, 20)); // Vertically centered in header

        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", title);

        if (g_pFontTitle) ImGui::PopFont();
        else ImGui::SetWindowFontScale(1.0f);

        ImGui::SetCursorPosY(headerHeight);
        ImGui::Separator();

        // ----------------------------------------------------------------------------------------
        // CONTENT
        // ----------------------------------------------------------------------------------------
        ImGui::BeginChild("Content", ImVec2(0, -70), false);

        if (g_activeMode == GuiMode::Config)
        {
            if (ImGui::BeginTabBar("ConfigTabs")) {
                if (ImGui::BeginTabItem("Global")) {
                    BeginCard("glob", {0.12f, 0.16f, 0.14f, 1.0f});
                    
                    ImGui::Checkbox("Ignore Non-Interactive", &g_configState.ignoreNonInteractive);
                    HelpMarker("Ignore non-interactive processes (services, scheduled tasks, SYSTEM processes).");

                    ImGui::Checkbox("Restore Priority on Exit", &g_configState.restoreOnExit);
                    HelpMarker("Restore original Win32PrioritySeparation value when program exits.");

                    ImGui::Checkbox("Lock Policy", &g_configState.lockPolicy);
                    HelpMarker("Prevent external interference from other tweaking tools.");

                    ImGui::Checkbox("Suspend Updates (Gaming)", &g_configState.suspendUpdates);
                    HelpMarker("Pause Windows Update and background transfers during gaming.");

                    ImGui::Separator();
                    
                    ImGui::Checkbox("Idle Revert Mode", &g_configState.idleRevert);
                    HelpMarker("Automatically revert to Browser Mode if system is idle for specified time and no game is currently running.");

                    // [FIX] Use InputInt for uniformity with other tabs
                    ImGui::InputInt("Idle Timeout", &g_configState.idleTimeoutSec);
                    HelpMarker("Time in seconds before idle mode activates.");

                    ImGui::Separator();

                    ImGui::Checkbox("Hung App Recovery", &g_configState.recovery);
                    HelpMarker("Automatically detect and boost hung applications to restore responsiveness.");

                    ImGui::Checkbox("Recovery Prompt", &g_configState.recoveryPrompt);
                    HelpMarker("Show a popup asking to restart the app if it stays hung for >15 seconds.");

                    ImGui::Separator();
                    
                    if (ImGui::Button("Restore Defaults")) {
                        g_configState.ignoreNonInteractive = true;
                        g_configState.restoreOnExit = true;
                        g_configState.lockPolicy = false;
                        g_configState.suspendUpdates = false;
                        g_configState.idleRevert = true;
                        g_configState.idleTimeoutSec = 300;
                        g_configState.recovery = true;
                        g_configState.recoveryPrompt = true;
                        strncpy_s(g_configState.iconTheme, "Default", 63);
                    }
                    HelpMarker("Restores global settings to recommended defaults (does not auto-save).");

                    ImGui::SameLine();

                    if (ImGui::Button("Save Settings", ImVec2(140, 32))) {
                        // Apply to Global State
                        g_ignoreNonInteractive.store(g_configState.ignoreNonInteractive);
                        g_restoreOnExit.store(g_configState.restoreOnExit);
                        g_lockPolicy.store(g_configState.lockPolicy);
                        g_suspendUpdatesDuringGames.store(g_configState.suspendUpdates);
                        g_idleRevertEnabled.store(g_configState.idleRevert);
                        g_idleTimeoutMs.store(g_configState.idleTimeoutSec * 1000);
                        g_responsivenessRecoveryEnabled.store(g_configState.recovery);
                        g_recoveryPromptEnabled.store(g_configState.recoveryPrompt);
                        
                        {
                            std::unique_lock lg(g_setMtx);
                            g_iconTheme = Utf8ToWide(g_configState.iconTheme);
                        }

                        // Save Explorer Config
                        ExplorerConfig ec;
                        ec.enabled = g_configState.expEnabled;
                        ec.idleThresholdMs = g_configState.expIdleThresholdSec * 1000;
                        ec.boostDwm = g_configState.boostDwm;
                        ec.boostIoPriority = g_configState.boostIo;
                        ec.disablePowerThrottling = g_configState.disableEco;
                        ec.preventShellPaging = g_configState.preventPaging;
                        ec.scanIntervalMs = g_configState.scanIntervalSec * 1000;
                        ec.debugLogging = g_configState.debugLog;
                        
                        SetExplorerConfigShadow(ec);
                        
                        // Save to File
                        SaveConfig();
                        g_reloadNow.store(true);
                        
                        //MessageBoxW(g_hwnd, L"Configuration saved successfully.", L"PMan", MB_OK);
                    }

                    EndCard();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Explorer")) {
                    BeginCard("exp", {0.14f, 0.14f, 0.16f, 1.0f});

                    ImGui::Checkbox("Enable Smart Shell Boost", &g_configState.expEnabled);
                    HelpMarker("Optimizes Windows UI only when system is truly idle. Admin rights required for DWM boosting.");

                    if (g_configState.expEnabled) {
                        // [FIX] Use InputInt for uniformity
                        ImGui::InputInt("Idle Threshold", &g_configState.expIdleThresholdSec);
                        HelpMarker("Time in seconds with no user input and no foreground game before boost activates.");

                        ImGui::Checkbox("Boost DWM", &g_configState.boostDwm);
                        HelpMarker("Also boost Desktop Window Manager (dwm.exe) for smoother animations.");

                        ImGui::Checkbox("Boost I/O Priority", &g_configState.boostIo);
                        HelpMarker("Apply High I/O priority to file operations (snappier folder loading).");

                        ImGui::Checkbox("Disable Power Throttling", &g_configState.disableEco);
                        HelpMarker("Disable 'Power Throttling' (EcoQoS) for Explorer/DWM.");

                        ImGui::Checkbox("Prevent Shell Paging", &g_configState.preventPaging);
                        HelpMarker("Prevents Windows from paging out Explorer/DWM during gaming.");

                        // [FIX] Use InputInt for uniformity
                        ImGui::InputInt("Scan Interval", &g_configState.scanIntervalSec);
                        HelpMarker("Time in seconds on how often to check for new Explorer windows.");
                    }
                    
                    ImGui::Separator();
                    if (ImGui::Button("Restore Defaults")) {
                        g_configState.expEnabled = true;
                        g_configState.expIdleThresholdSec = 15;
                        g_configState.boostDwm = true;
                        g_configState.boostIo = false;
                        g_configState.disableEco = true;
                        g_configState.preventPaging = true;
                        g_configState.scanIntervalSec = 5;
                        g_configState.debugLog = false;
                    }

                    ImGui::SameLine();

                    if (ImGui::Button("Save Settings", ImVec2(140, 32))) {
                        // Apply Explorer Config
                        ExplorerConfig ec;
                        ec.enabled = g_configState.expEnabled;
                        ec.idleThresholdMs = g_configState.expIdleThresholdSec * 1000;
                        ec.boostDwm = g_configState.boostDwm;
                        ec.boostIoPriority = g_configState.boostIo;
                        ec.disablePowerThrottling = g_configState.disableEco;
                        ec.preventShellPaging = g_configState.preventPaging;
                        ec.scanIntervalMs = g_configState.scanIntervalSec * 1000;
                        ec.debugLogging = g_configState.debugLog;

                        SetExplorerConfigShadow(ec);
                        SaveConfig();
                        g_reloadNow.store(true);

                        //MessageBoxW(g_hwnd, L"Explorer settings saved successfully.", L"PMan", MB_OK);
                    }

                    EndCard();
                    ImGui::EndTabItem();
                }

                // [PATCH] Auto-Select Policy Tab if requested
                int polFlags = 0;
                if (g_requestedTab == "Policy") {
                    polFlags = ImGuiTabItemFlags_SetSelected;
                    g_requestedTab = ""; // Consumed
                }

                if (ImGui::BeginTabItem("Policy", nullptr, polFlags)) {
                    BeginCard("pol", {0.14f, 0.10f, 0.10f, 1.0f});
                    
                    // [PATCH] Preset Buttons
                    // Dynamic layout: Calculates exact width to fit 5 buttons in one row
                    float availW = ImGui::GetContentRegionAvail().x;
                    float gap = ImGui::GetStyle().ItemSpacing.x;
                    float btnW = (availW - (gap * 4.0f)) / 5.0f;

                    if (ImGui::Button("Safest", ImVec2(btnW, 32))) {
                        g_configState.maxBudget = 150;
                        g_configState.cpuVar = 0.01f; // Strict 0.1% margin
                        g_configState.latVar = 0.02f;
                        g_configState.allowThrottleMild = true;
                        g_configState.allowThrottleAggressive = false;
                        g_configState.allowOptimize = true;
                        g_configState.allowSuspend = false;
                        g_configState.allowPressure = false;
                        g_configState.allowMaintain = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Balanced", ImVec2(btnW, 32))) {
                        g_configState.maxBudget = 300;
                        g_configState.cpuVar = 0.50f; // 0.7% margin (Standard)
                        g_configState.latVar = 1.00f;
                        g_configState.allowThrottleMild = true;
                        g_configState.allowThrottleAggressive = true;
                        g_configState.allowOptimize = true;
                        g_configState.allowSuspend = false;
                        g_configState.allowPressure = false;
                        g_configState.allowMaintain = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Gamer", ImVec2(btnW, 32))) {
                        g_configState.maxBudget = 1000;
                        g_configState.cpuVar = 4.0f;  // 2.0% margin (Aggressive)
                        g_configState.latVar = 8.0f;
                        g_configState.allowThrottleMild = true;
                        g_configState.allowThrottleAggressive = true;
                        g_configState.allowOptimize = true;
                        g_configState.allowSuspend = true;
                        g_configState.allowPressure = true;
                        g_configState.allowMaintain = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Insomnia", ImVec2(btnW, 32))) {
                        g_configState.maxBudget = 5000;
                        g_configState.cpuVar = 10.0f; // 3.1% margin (Very Aggressive)
                        g_configState.latVar = 20.0f;
                        g_configState.allowThrottleMild = true;
                        g_configState.allowThrottleAggressive = true;
                        g_configState.allowOptimize = true;
                        g_configState.allowSuspend = true;
                        g_configState.allowPressure = true;
                        g_configState.allowMaintain = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Tetris", ImVec2(btnW, 32))) {
                        g_configState.maxBudget = 10000;
                        g_configState.cpuVar = 25.0f; // 5.0% margin (ENGINE LIMIT)
                        g_configState.latVar = 50.0f;
                        g_configState.allowThrottleMild = true;
                        g_configState.allowThrottleAggressive = true;
                        g_configState.allowOptimize = true;
                        g_configState.allowSuspend = true;
                        g_configState.allowPressure = true;
                        g_configState.allowMaintain = true;
                    }
                    ImGui::Separator();

                    ImGui::InputInt("Authority Budget", &g_configState.maxBudget);
                    HelpMarker("Finite authority limit. Each action consumes budget.\nWhen exhausted, the system permanently reverts to Maintain until externally reset.");

                    // [PATCH] Enforce Safety Limits (0.1% to Engine Max)
                    // Min 0.001 ensures the AI isn't permanently frozen.
                    // Max 25.0/50.0 matches decision_arbiter.h hard limits.
                    ImGui::InputFloat("CPU Variance", &g_configState.cpuVar, 0.005f, 0.01f, "%.3f");
                    if (g_configState.cpuVar > 25.0f) g_configState.cpuVar = 25.0f; // Matches MAX_CPU_VARIANCE
                    if (g_configState.cpuVar < 0.001f) g_configState.cpuVar = 0.001f;
                    HelpMarker("Confidence threshold. Lower values require more predictable\nCPU behavior before actions are allowed.");

                    ImGui::InputFloat("Latency Variance", &g_configState.latVar, 0.005f, 0.01f, "%.3f");
                    if (g_configState.latVar > 50.0f) g_configState.latVar = 50.0f; // Matches MAX_LAT_VARIANCE
                    if (g_configState.latVar < 0.001f) g_configState.latVar = 0.001f;
                    HelpMarker("Confidence threshold for latency prediction.\nHigh variance disables authority regardless of intent.");

                    ImGui::Separator();
                    ImGui::Text("Allowed Actions:");

                    // [FIX] Force "Stability" to be always enabled.
                    // "Intelligence is the ability to choose NOT to act."
                    //g_configState.allowMaintain = true;
                    //ImGui::BeginDisabled();
                    ImGui::Checkbox("Stability (Inaction)", &g_configState.allowMaintain);
                    //ImGui::EndDisabled();
                    // [PATCH] Corrected description: Disabling 'Maintain' causes syscall spam, reducing performance.
                    HelpMarker("The 'Do Nothing' choice. Required for stability. Without this, the\nAI is forced to constantly intervene, wasting CPU cycles on unnecessary API calls.\nWARNING: Unchecking this will likely INCREASE input lag.");

                    ImGui::Checkbox("Throttle (Mild)", &g_configState.allowThrottleMild);
                    HelpMarker("Allows mild, reversible priority reduction.\nSubject to policy, verdict, confidence, and budget.");

                    ImGui::Checkbox("Throttle (Aggressive)", &g_configState.allowThrottleAggressive);
                    HelpMarker("Allows stronger throttling.\nMay be vetoed by policy, confidence, or external authority.");

                    ImGui::Checkbox("Optimize Memory", &g_configState.allowOptimize);
                    HelpMarker("Allows memory cleanup actions.\nExecution depends on sandbox safety and external permission.");

                    ImGui::Checkbox("Suspend Services", &g_configState.allowSuspend);
                    HelpMarker("High-impact action.\nRequires explicit policy and external authorization.");

                    ImGui::Checkbox("Pressure Relief", &g_configState.allowPressure);
                    HelpMarker("Emergency action category. Rarely permitted and strictly audited.");

                    if (ImGui::Button("Apply Policy", ImVec2(140, 32))) {
                        bool proceed = true;

                        // [PATCH] Safety Warning for High Variance
                        // Warn if user sets variance >= 1.0 (Chaos Mode), but allow it.
                        if (g_configState.cpuVar >= 1.0f || g_configState.latVar >= 1.0f) {
                            if (MessageBoxW(g_hwnd, 
                                L"DANGER: You are setting extremely high Variance (>= 1.0).\n\n"
                                L"This effectively DISABLES the stability governor. "
                                L"The AI will make changes even during extreme lag or CPU spikes.\n\n"
                                L"Are you sure you want to remove these safety rails?", 
                                L"PMan Policy Warning", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
                                proceed = false;
                            }
                        }

                        if (proceed) {
                            PolicyLimits limits;
                            limits.maxAuthorityBudget = g_configState.maxBudget;
                            limits.minConfidence.cpuVariance = g_configState.cpuVar;
                            limits.minConfidence.latencyVariance = g_configState.latVar;
                            
                            if (g_configState.allowThrottleMild) limits.allowedActions.insert((int)BrainAction::Throttle_Mild);
                            if (g_configState.allowThrottleAggressive) limits.allowedActions.insert((int)BrainAction::Throttle_Aggressive);
                            
                            if (g_configState.allowMaintain) limits.allowedActions.insert((int)BrainAction::Maintain);

                            if (g_configState.allowOptimize) {
                                limits.allowedActions.insert((int)BrainAction::Optimize_Memory);
                                limits.allowedActions.insert((int)BrainAction::Optimize_Memory_Gentle);
                            }
                            if (g_configState.allowSuspend) limits.allowedActions.insert((int)BrainAction::Suspend_Services);
                            if (g_configState.allowPressure) {
                                limits.allowedActions.insert((int)BrainAction::Release_Pressure);
                                limits.allowedActions.insert((int)BrainAction::Shield_Foreground);
                            }

                            // [FIX] Implicitly Allow Core Actions (Boost)
                            // Boost is required for the Governor but hidden from simple toggles to prevent user error
                            limits.allowedActions.insert((int)BrainAction::Boost_Process);
                            
                            // Ensure Maintain is present if user checked it (redundant safety)
                            if (g_configState.allowMaintain) limits.allowedActions.insert((int)BrainAction::Maintain);
                            
                            // Save Policy
                            if (PManContext::Get().subs.policy) {
                                PManContext::Get().subs.policy->Save(GetLogPath() / L"policy.json", limits);
                                g_reloadNow.store(true); // Trigger hot-reload
                            }
                        }
                    }

                    EndCard();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Verdict")) {
                    BeginCard("verd", {0.14f, 0.14f, 0.18f, 1.0f});
                    
                    ImGui::TextDisabled("External Safety Override System");
                    HelpMarker("A global safety switch that allows you (or external tools) to forcefully\nALLOW, DENY, or LIMIT the AI's control over your PC for a set period of time.");
                    
                    ImGui::Separator();

                    const char* items[] = { "ALLOW", "DENY", "CONSTRAIN" };
                    ImGui::Combo("Verdict Status", &g_configState.verdictIdx, items, IM_ARRAYSIZE(items));
                    HelpMarker("ALLOW: AI has full control.\nDENY: AI is completely disabled.\nCONSTRAIN: AI is restricted to specific safe actions only.");
                    
                    ImGui::InputInt("Duration", &g_configState.durationHours);
                    HelpMarker("Time in hours on how long this override should last before returning to normal operation.");

                    ImGui::Separator();

                    if (ImGui::Button("Revoke Authority Now", ImVec2(180, 32))) {
                        ExternalVerdict::SaveVerdict(GetLogPath() / L"verdict.json", VerdictType::DENY, 3600);
                    }
                    HelpMarker("PANIC BUTTON: Immediately stops the AI from doing anything for 1 hour.");

                    ImGui::SameLine();
                    
                    if (ImGui::Button("Grant Authority", ImVec2(180, 32))) {
                        VerdictType type = VerdictType::ALLOW;
                        if (g_configState.verdictIdx == 1) type = VerdictType::DENY;
                        if (g_configState.verdictIdx == 2) type = VerdictType::CONSTRAIN;
                        
                        ExternalVerdict::SaveVerdict(GetLogPath() / L"verdict.json", type, g_configState.durationHours * 3600);
                    }
                    HelpMarker("Applies the selected Status and Duration.");

                    EndCard();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Lists")) {
                    BeginCard("lists", {0.14f, 0.14f, 0.16f, 1.0f});

                    ImGui::TextDisabled("Manage Process Lists");
                    HelpMarker("Here you can categorize your applications to ensure they get the correct optimization strategy:\n\n"
                        "- Games: Assigned High Priority and fixed short quantum (0x28) for maximum frame stability.\n"
                        "- Browsers: Assigned Above Normal priority and variable quantum (0x26) for responsiveness.\n"
                        "- Video Players: Boosted to prevent playback stuttering.\n"
                        "- Custom Launchers: Treated as background noise (Low Priority) to save CPU for the actual game.\n"
                        "- Ignored Processes: System components that PMan should never touch or modify.");
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (ImGui::Button("Edit Games List", ImVec2(-1, 32))) EditorManager::OpenConfigAtSection(L"[games]");
                    if (ImGui::Button("Edit Browsers List", ImVec2(-1, 32))) EditorManager::OpenConfigAtSection(L"[browsers]");
                    if (ImGui::Button("Edit Video Players", ImVec2(-1, 32))) EditorManager::OpenConfigAtSection(L"[video_players]");
                    
                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();

                    // [FIX] Redirect to config.ini sections instead of opening orphan files
                    if (ImGui::Button("Edit Custom Launchers", ImVec2(-1, 32))) EditorManager::OpenConfigAtSection(L"[custom_launchers]");
                    if (ImGui::Button("Edit Ignored Processes", ImVec2(-1, 32))) EditorManager::OpenConfigAtSection(L"[ignored_processes]");

                    EndCard();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Debug")) {
                    BeginCard("dbg", {0.15f, 0.10f, 0.10f, 1.0f});

                    ImGui::TextDisabled("Fault Injection (Adversarial Testing)");
                    ImGui::Separator();

                    ImGui::Checkbox("Simulate Ledger Write Fail", &g_configState.faultLedger);
                    HelpMarker("Simulates a failure in the audit system.\nVerifies that the AI reports the error and stops.");

                    ImGui::Checkbox("Simulate Budget Corruption", &g_configState.faultBudget);
                    HelpMarker("Simulates a budget tracking error.\nVerifies that the AI locks down to prevent unauthorized usage.");

                    ImGui::Checkbox("Simulate Sandbox Error", &g_configState.faultSandbox);
                    HelpMarker("Simulates a failure in the safety sandbox.\nVerifies that the AI correctly reports the crash.");

                    ImGui::Checkbox("Simulate Invalid Intent", &g_configState.faultIntent);
                    HelpMarker("Simulates a logic mismatch.\nVerifies that the AI rejects the action as unsafe.");

                    ImGui::Checkbox("Simulate Invalid Confidence", &g_configState.faultConfidence);
                    HelpMarker("Simulates unreliable data.\nVerifies that the AI reverts to a safe state.");

                    ImGui::Spacing();
                    ImGui::TextDisabled("Logging & Diagnostics");
                    ImGui::Separator();

                    ImGui::Checkbox("Explorer Debug Logging", &g_configState.debugLog);
                    HelpMarker("Enables verbose logging for the Smart Shell Booster subsystem.");

                    ImGui::Spacing();
                    ImGui::Separator();

                    if (ImGui::Button("Apply Debug Settings", ImVec2(180, 32))) {
                        // Apply Faults
                        auto& f = PManContext::Get().fault;
                        f.ledgerWriteFail = g_configState.faultLedger;
                        f.budgetCorruption = g_configState.faultBudget;
                        f.sandboxError = g_configState.faultSandbox;
                        f.intentInvalid = g_configState.faultIntent;
                        f.confidenceInvalid = g_configState.faultConfidence;
                        Log("[USER] Debug settings applied.");

                        // Apply Debug Logging
                        ExplorerConfig ec = GetExplorerConfigShadow();
                        ec.debugLogging = g_configState.debugLog;
                        SetExplorerConfigShadow(ec);
                        SaveConfig();
                        g_reloadNow.store(true);
                    }

                    EndCard();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("TuneUp")) {
                    if (ImGui::BeginTabBar("TweakTabs")) {
                        if (ImGui::BeginTabItem("Recommended")) {
                            BeginCard("rec", {0.12f, 0.16f, 0.14f, 1.0f});
                            ImGui::Checkbox("Network Optimizations", &g_config.network);
                            HelpMarker("Improves TCP/IP and latency behavior.");
                            ImGui::Checkbox("Privacy & Telemetry", &g_config.privacy);
                            HelpMarker("Disables diagnostics and tracking.");
                            ImGui::Checkbox("Visual Effects", &g_config.explorer);
                            HelpMarker("Reduces UI overhead.");
                            ImGui::Checkbox("Power Plan Tuning", &g_config.power);
                            HelpMarker("Optimizes power behavior.");
                            EndCard();
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem("Functional")) {
                            BeginCard("func", {0.14f, 0.14f, 0.18f, 1.0f});
                            ImGui::Checkbox("Set Services to Manual", &g_config.services);
                            HelpMarker("Sets non-critical services to Manual.");
                            ImGui::Checkbox("Disable Location Services", &g_config.location);
                            HelpMarker("Globally disables Windows location APIs.");
                            ImGui::Checkbox("Disable GameDVR / Xbox", &g_config.dvr);
                            HelpMarker("Disables background recording.");
                            EndCard();
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem("Aggressive")) {
                            BeginCard("agg", {0.18f, 0.10f, 0.10f, 1.0f});
                            ImGui::Checkbox("Remove UWP Bloatware", &g_config.bloatware);
                            HelpMarker("Permanent removal of bundled apps.");
                            EndCard();
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem("Future")) {
                            BeginCard("future", {0.10f, 0.10f, 0.14f, 1.0f});
                            ImGui::TextDisabled("Reserved for future expansion:");
                            ImGui::BulletText("Kernel scheduling controls");
                            ImGui::BulletText("Advanced memory management");
                            ImGui::BulletText("Per-app CPU affinity");
                            ImGui::BulletText("I/O prioritization");
                            EndCard();
                            ImGui::EndTabItem();
                        }
                        ImGui::EndTabBar();
                    }
                    ImGui::Separator();
                    if (ImGui::Button("Apply Tweaks", ImVec2(140, 32))) {
                        if (ApplyStaticTweaks(g_config)) {
                            SaveTweakPreferences(g_config);
                            MessageBoxW(g_hwnd, L"Your selected optimizations have been applied.", L"Success", MB_OK | MB_ICONINFORMATION);
                        }
                    }
                    ImGui::EndTabItem();
                }

                ImGui::EndTabBar();
            }
        }
        else if (g_activeMode == GuiMode::About)
        {
            ImGui::Spacing(); ImGui::Spacing();
            
            // Centered About Text
            std::string ver = WideToUtf8(GetCurrentExeVersion().c_str());
            std::string verText = "Priority Manager v" + ver;
            
            auto CenterText = [](const char* text) {
                float winWidth = ImGui::GetWindowSize().x;
                float textWidth = ImGui::CalcTextSize(text).x;
                ImGui::SetCursorPosX((winWidth - textWidth) * 0.5f);
                ImGui::Text("%s", text);
            };

            if (g_pFontTitle) ImGui::PushFont(g_pFontTitle);
            CenterText(verText.c_str());
            if (g_pFontTitle) ImGui::PopFont();
            
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
            CenterText("By Ian Anthony R. Tancinco");
            ImGui::PopStyleColor();

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

            ImGui::TextWrapped("Automated Windows Priority & Affinity Manager designed for high-performance low-latency gaming.");
            ImGui::Spacing();
            ImGui::TextWrapped("Copyright (c) 2025-2026 Ian Anthony R. Tancinco. All rights reserved.");
        }
        else if (g_activeMode == GuiMode::Help)
        {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Command Line Usage:");
            ImGui::Separator();
            
            if (ImGui::BeginChild("HelpScroll")) {
                ImGui::Text("pman.exe [OPTIONS]");
                ImGui::Spacing();
                
                struct Opt { const char* cmd; const char* desc; };
                Opt options[] = {
                    {"--help, -h, /?", "Show this help message"},
                    {"--uninstall", "Stop instances and remove startup task"},
                    {"--silent, /S", "Run operations without message boxes"},
                    {"--paused", "Start in paused mode"},
                    {"--guard", "(Internal) Registry safety guard"}
                };

                for (const auto& opt : options) {
                    ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", opt.cmd);
                    ImGui::SameLine(200);
                    ImGui::Text("%s", opt.desc);
                }
                ImGui::EndChild();
            }
        }
        else if (g_activeMode == GuiMode::LogViewer)
        {
            UpdateLogContent();

            // [FIX] Calculate dimensions safely inside the frame loop
            if (g_logBuffer.size() != g_logPrevSize) {
                 g_logMaxWidth = ImGui::CalcTextSize(g_logBuffer.c_str()).x;
                 g_logLineCount = (int)std::count(g_logBuffer.begin(), g_logBuffer.end(), '\n') + 1;
                 g_logPrevSize = g_logBuffer.size();
            }

            if (ImGui::Button("Clear Log")) { 
                g_logBuffer.clear(); 
                g_logMaxWidth = 0.0f; 
                g_logLineCount = 0;
            }
            ImGui::SameLine();
            ImGui::Checkbox("Auto-scroll", &g_logAutoScroll);
            ImGui::SameLine();
            ImGui::TextDisabled("%d bytes", (int)g_logBuffer.size());

            ImGui::Separator();

            ImGui::BeginChild("LogRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            
            ImGui::PushFont(g_pFontRegular);
            
            if (g_logAutoScroll) {
                // Auto-scroll mode: non-interactive, just display
                ImGui::TextUnformatted(g_logBuffer.c_str());
                ImGui::SetScrollHereY(1.0f);
            } else {
                // Manual mode: selectable/copyable
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
                ImGuiInputTextFlags flags = ImGuiInputTextFlags_ReadOnly;
                ImVec2 size = ImGui::GetContentRegionAvail();
                
                // Force width to match text content + padding to prevent wrapping
                // This enables the parent window's horizontal scrollbar
                float contentWidth = (std::max)(size.x, g_logMaxWidth + 20.0f);
                
                // [FIX] Calculate full height to force parent-managed vertical scrolling
                // If we restrict height to size.y, the widget's internal scrollbar appears off-screen (due to wide width)
                float minHeight = (std::max)(size.y, g_logLineCount * ImGui::GetTextLineHeight() + ImGui::GetStyle().FramePadding.y * 2);

                // [FIX] Safe buffer access for empty strings
                // Use a mutable empty char for safety if buffer is empty
                static char empty = 0;
                ImGui::InputTextMultiline("##log", g_logBuffer.empty() ? &empty : &g_logBuffer[0], g_logBuffer.size() + 1, 
                    ImVec2(contentWidth, minHeight), flags);
                ImGui::PopStyleColor();
            }
            
            ImGui::PopFont();
            ImGui::EndChild();
        }

        ImGui::EndChild();
        ImGui::Separator();

        // ----------------------------------------------------------------------------------------
        // FOOTER
        // ----------------------------------------------------------------------------------------
        // Single Close Button for all windows (Apply buttons are now inside tabs)
        float width = 120.0f;
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - width) * 0.5f);
        if (ImGui::Button("Close", ImVec2(width, 36))) {
            g_isOpen = false;
            ShowWindow(g_hwnd, SW_HIDE);
        }

        if (g_pFontRegular) ImGui::PopFont(); // Pop Main Font

        ImGui::End();

        // ----------------------------------------------------------------------------------------
        // PRESENT
        // ----------------------------------------------------------------------------------------
        ImGui::Render();
        // [FIX] Clear to transparent (0,0,0,0) so DWM can render the desktop behind the corners
        const float clearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        HRESULT hr = g_pSwapChain->Present(1, 0);
		if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
			RecoverFromDeviceLoss();
		}
	}

	void RecoverFromDeviceLoss() {
        if (!g_isInitialized) return;
        
        // 1. Invalidate ImGui resources associated with the old device
        ImGui_ImplDX11_InvalidateDeviceObjects();
        
        // 2. Tear down the old D3D device
        CleanupDeviceD3D();
        
        // 3. Recreate the device
        if (CreateDeviceD3D(g_hwnd)) {
            // 4. Re-initialize the ImGui backend with the new pointers
            // Note: We perform a partial re-bind here. 
            // Ideally, we should Shutdown/Init, but swapping pointers works for simple recovery.
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
            Log("[GUI] Recovered from D3D Device Loss/Reset.");
        } else {
            Log("[GUI] CRITICAL: Failed to recover from Device Loss.");
        }
    }

	// ============================================================================================
	// D3D / Win32
	// ============================================================================================
	bool CreateDeviceD3D(HWND hWnd) {
        DXGI_SWAP_CHAIN_DESC sd{};
        sd.BufferCount = 2;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd;
        sd.SampleDesc.Count = 1;
        sd.Windowed = TRUE;

        if (D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            0,
            nullptr,
            0,
            D3D11_SDK_VERSION,
            &sd,
            &g_pSwapChain,
            &g_pd3dDevice,
            nullptr,
            &g_pd3dDeviceContext) != S_OK)
            return false;

        CreateRenderTarget();
        return true;
    }

    void CleanupDeviceD3D() {
        CleanupRenderTarget();
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    }

    void CreateRenderTarget() {
        ID3D11Texture2D* backBuffer = nullptr;
        g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
        g_pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, &g_mainRenderTargetView);
        backBuffer->Release();
    }

    void CleanupRenderTarget() {
        if (g_mainRenderTargetView) {
            g_mainRenderTargetView->Release();
            g_mainRenderTargetView = nullptr;
        }
    }

    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        if (msg == WM_CLOSE) {
            g_isOpen = false;
            ShowWindow(hWnd, SW_HIDE);
            return 0;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}
