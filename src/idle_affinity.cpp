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

#include "idle_affinity.h"
#include "globals.h"
#include "utils.h"
#include "logger.h"
#include "sysinfo.h"
#include <tlhelp32.h>
#include <vector>
#include <shared_mutex> // Required for g_setMtx

// Helper implementation of the classification logic
static ProcessNetClass ClassifyProcessActivity(DWORD pid, const std::wstring& exeName) 
{
    // [ENHANCEMENT] PID-based Safety Checks
    // Explicitly protect System (4), Idle (0), and Own Process to prevent accidental parking
    // This utilizes the 'pid' parameter to enforce safety at the kernel object level
    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) 
        return ProcessNetClass::SystemCritical;

    // 1. Critical System Processes (Already checked by caller via IsSystemCriticalProcess, but safety first)
    if (IsSystemCriticalProcess(exeName)) return ProcessNetClass::SystemCritical;

    // 2. User Critical (Games, Video Players) - Do NOT park
    {
        std::shared_lock lock(g_setMtx);
        if (g_games.count(exeName) || g_oldGames.count(exeName) || 
            g_videoPlayers.count(exeName) || g_gameWindows.count(exeName)) 
            return ProcessNetClass::UserCritical;
    }

    // 3. Heuristic Classification
    if (exeName == L"discord.exe" || exeName == L"teams.exe" || exeName == L"zoom.exe" || 
        exeName == L"obs64.exe" || exeName == L"obs.exe") 
        return ProcessNetClass::LatencySensitive;

    // 4. Targets for Parking (Downloaders, Browsers, Background)
    if (exeName == L"steam.exe" || exeName == L"epigameslauncher.exe" || 
        exeName == L"battle.net.exe" || exeName == L"chrome.exe" || 
        exeName == L"msedge.exe" || exeName == L"firefox.exe") 
        return ProcessNetClass::NetworkBound;

    // Default to Unknown (Candidates for parking if not critical)
    return ProcessNetClass::Unknown; 
}

void IdleAffinityManager::Initialize()
{
    // Safety: Only enable on systems with sufficient RAM and Cores
    if (g_physicalCoreCount < 4) {
        m_enabled = false;
        Log("[IDLE-PARK] Feature disabled: Requires Quad-Core or better CPU");
        return;
    }
}

void IdleAffinityManager::Shutdown()
{
    if (m_isIdle.load()) {
        RestoreAllAffinity();
    }
}

void IdleAffinityManager::UpdateConfig(bool enabled, int reservedCores, uint32_t minRamGB)
{
    m_enabled = enabled;
    m_reservedCores = reservedCores;
    m_minRamGB = minRamGB;
}

bool IdleAffinityManager::IsSafeToPark()
{
    if (!m_enabled.load()) return false;
    
    // RAM Check
    MEMORYSTATUSEX ms = {sizeof(ms)};
    if (GlobalMemoryStatusEx(&ms)) {
        uint64_t totalGB = ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL);
        if (totalGB < m_minRamGB.load()) return false;
    }

    // Don't park if a game is running (even if no input) to prevent messing up the game
    // if the user is watching a cutscene or waiting in a lobby.
    if (g_sessionLocked.load()) return false;

    return true;
}

void IdleAffinityManager::OnIdleStateChanged(bool isIdle)
{
    bool wasIdle = m_isIdle.exchange(isIdle);
    if (wasIdle == isIdle) return; // No change

    if (isIdle) {
        if (IsSafeToPark()) {
            Log("[IDLE-PARK] System idle detected. Parking background processes...");
            ApplyIdleAffinity();
        }
    } else {
        RestoreAllAffinity();
        Log("[IDLE-PARK] Activity detected. Restored process affinity.");
    }
}

void IdleAffinityManager::OnProcessStart(DWORD pid)
{
    if (!m_isIdle.load()) {
        UNREFERENCED_PARAMETER(pid);
        return;
    }
    if (!IsSafeToPark()) return;

    // Calculate Park Mask (Last N cores)
    int reserved = m_reservedCores.load();
    if (reserved >= static_cast<int>(g_physicalCoreCount)) reserved = g_physicalCoreCount - 1;
    
    DWORD_PTR parkMask = 0;
    for (int i = 0; i < reserved; i++) {
        parkMask |= (1ULL << (g_physicalCoreCount - 1 - i));
    }
    
    SetProcessIdleAffinity(pid, parkMask);
}

void IdleAffinityManager::ApplyIdleAffinity()
{
	// [PERF FIX] Rate limit to prevent thrashing if idle state flickers
    static uint64_t lastRun = 0;
    uint64_t now = GetTickCount64();
    if (now - lastRun < 10000) return; // Max once every 10s
    lastRun = now;
	
    // [CRASH FIX] Wrap in try-catch to prevent thread termination on std::bad_alloc
    try {
        // Calculate Park Mask
        int reserved = m_reservedCores.load();
        if (reserved >= static_cast<int>(g_physicalCoreCount)) reserved = g_physicalCoreCount - 1;
        
        DWORD_PTR parkMask = 0;
        for (int i = 0; i < reserved; i++) {
            parkMask |= (1ULL << (g_physicalCoreCount - 1 - i));
        }

        // [FIX] Scoped lock to prevent recursive deadlock when calling SetProcessIdleAffinity
        {
            std::lock_guard lock(m_mtx);
            m_originalAffinity.clear();
        }

        // [CRASH FIX] Use UniqueHandle for RAII safety (prevents leaks on exception)
        UniqueHandle hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnap.get() == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(hSnap.get(), &pe)) {
            do {
                // Safety Checks
                if (pe.th32ProcessID <= 4) continue;
                if (pe.th32ProcessID == GetCurrentProcessId()) continue; // Never park self

                // [PERF] Use raw string reference if possible, but wstring is safer for utils
                std::wstring exe = pe.szExeFile;
                asciiLower(exe);
                
                if (IsSystemCriticalProcess(exe)) continue; // Never touch Defender/OS
                
                // Classification Check
                ProcessNetClass type = ClassifyProcessActivity(pe.th32ProcessID, exe);
                
                // Only park background/network/unknown. SKIP UserCritical (Games) and LatencySensitive (VoIP).
                if (type == ProcessNetClass::NetworkBound || 
                    type == ProcessNetClass::Unknown || 
                    type == ProcessNetClass::BulkBackground) 
                {
                    SetProcessIdleAffinity(pe.th32ProcessID, parkMask);
                }

            } while (Process32NextW(hSnap.get(), &pe));
        }
    } catch (const std::exception& e) {
        Log("[IDLE-PARK] Error applying affinity: " + std::string(e.what()));
    } catch (...) {
        Log("[IDLE-PARK] Unknown error applying affinity");
    }
}

void IdleAffinityManager::SetProcessIdleAffinity(DWORD pid, DWORD_PTR targetMask)
{
    // [CRASH FIX] Use UniqueHandle to guarantee closure
    UniqueHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProcess) return;

    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;

    if (GetProcessAffinityMask(hProcess.get(), &processAffinity, &systemAffinity))
    {
        // Don't touch if already set or incompatible
        if ((processAffinity & targetMask) == 0) {
             return; // UniqueHandle closes hProcess automatically
        }

        // Store original (if not already stored)
        {
            std::lock_guard lock(m_mtx);
            if (m_originalAffinity.find(pid) == m_originalAffinity.end()) {
                m_originalAffinity[pid] = processAffinity;
            }
        }

        // Apply Park Mask
        SetProcessAffinityMask(hProcess.get(), targetMask & systemAffinity);
    }
}

void IdleAffinityManager::RestoreAllAffinity()
{
    // Offload to detached thread to prevent Main Thread freeze
    std::thread([this]() {
        std::lock_guard lock(m_mtx);
        if (m_originalAffinity.empty()) return;

        int processed = 0;
        for (const auto& [pid, originalMask] : m_originalAffinity)
        {
            UniqueHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid));
            if (hProcess) {
                SetProcessAffinityMask(hProcess.get(), originalMask);
            }

            // Yield every 5 processes to allow scheduler recovery
            if (++processed % 5 == 0) Sleep(20); 
        }
        m_originalAffinity.clear();
    }).detach();
}
