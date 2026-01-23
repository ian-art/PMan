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

#include <d3d11.h>
#include <tchar.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")

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

    // ============================================================================================
    // Forward declarations
    // ============================================================================================
    bool    CreateDeviceD3D(HWND hWnd);
    void    CleanupDeviceD3D();
    void    CreateRenderTarget();
    void    CleanupRenderTarget();
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

        ImGui_ImplWin32_Init(g_hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        LoadTweakPreferences(g_config);
        g_isInitialized = true;
    }

    void ShowTuneUpWindow() {
        if (!g_isInitialized) Init();
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
        float titleScale = 2.2f;

        ImGui::SetWindowFontScale(titleScale);
        ImVec2 textSize = ImGui::CalcTextSize(title);
        ImGui::SetWindowFontScale(1.0f);

        float centerX = (ImGui::GetWindowWidth() - textSize.x) * 0.5f;
        ImGui::SetCursorPos(ImVec2(centerX, 20));

        ImGui::SetWindowFontScale(titleScale);
        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", title);
        ImGui::SetWindowFontScale(1.0f);

        ImGui::SetCursorPosY(headerHeight);
        ImGui::Separator();

        // ----------------------------------------------------------------------------------------
        // CONTENT
        // ----------------------------------------------------------------------------------------
        ImGui::BeginChild("Content", ImVec2(0, -70), false);

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

        ImGui::EndChild();
        ImGui::Separator();

        // ----------------------------------------------------------------------------------------
        // FOOTER
        // ----------------------------------------------------------------------------------------
        if (ImGui::Button("Apply", ImVec2(120, 36))) {
            if (ApplyStaticTweaks(g_config)) {
                SaveTweakPreferences(g_config);
                MessageBoxW(
                    g_hwnd,
                    L"Selected optimizations applied.\nRestart recommended.",
                    L"Success",
                    MB_OK | MB_ICONINFORMATION
                );
            }
            g_isOpen = false;
            ShowWindow(g_hwnd, SW_HIDE);
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 36))) {
            g_isOpen = false;
            ShowWindow(g_hwnd, SW_HIDE);
        }

        ImGui::End();

        // ----------------------------------------------------------------------------------------
        // PRESENT
        // ----------------------------------------------------------------------------------------
        ImGui::Render();
        const float clearColor[4] = {0.05f, 0.05f, 0.07f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
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
        if (g_pSwapChain) g_pSwapChain->Release();
        if (g_pd3dDeviceContext) g_pd3dDeviceContext->Release();
        if (g_pd3dDevice) g_pd3dDevice->Release();
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
