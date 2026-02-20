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
#include "heartbeat.h"
#include "context.h"
#include "logger.h"

HeartbeatSystem::HeartbeatSystem() = default;

HeartbeatSystem::~HeartbeatSystem() {
    Shutdown();
}

bool HeartbeatSystem::Initialize() {
    auto& runtime = PManContext::Get().runtime;

    // Create Shared Memory for Watchdog monitoring (Local\PManHeartbeat)
    // Uses UniqueHandle for RAII compliance
    runtime.hHeartbeatMap.reset(
        CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(HeartbeatSharedMemory), L"Local\\PManHeartbeat")
    );

    if (runtime.hHeartbeatMap) {
        runtime.pHeartbeat = (HeartbeatSharedMemory*)MapViewOfFile(
            runtime.hHeartbeatMap.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(HeartbeatSharedMemory)
        );

        if (runtime.pHeartbeat) {
            // Initialize heartbeat data
            runtime.pHeartbeat->pid = GetCurrentProcessId();
            runtime.pHeartbeat->counter.store(0);
            runtime.pHeartbeat->last_tick = GetTickCount64();
            Log("[INIT] Watchdog Heartbeat initialized (Dedicated Thread).");
        } else {
            Log("[ERROR] Failed to map Watchdog Heartbeat memory.");
            return false;
        }
    } else {
        Log("[ERROR] Failed to create Watchdog Heartbeat shared memory.");
        return false;
    }

    m_running.store(true);
    m_worker = std::thread(&HeartbeatSystem::WorkerThread, this);
    
    // Lower priority so heartbeat thread doesn't interfere with core functionality
    SetThreadPriority(m_worker.native_handle(), THREAD_PRIORITY_LOWEST);

    return true;
}

void HeartbeatSystem::Shutdown() {
    if (m_running.exchange(false)) {
        if (m_worker.joinable()) {
            m_worker.join();
        }
    }

    auto& runtime = PManContext::Get().runtime;
    if (runtime.pHeartbeat) {
        UnmapViewOfFile(runtime.pHeartbeat);
        runtime.pHeartbeat = nullptr;
    }
    if (runtime.hHeartbeatMap) {
        runtime.hHeartbeatMap.reset();
    }
}

void HeartbeatSystem::WorkerThread() {
    auto& runtime = PManContext::Get().runtime;
    while (m_running.load()) {
        if (runtime.pHeartbeat) {
            runtime.pHeartbeat->counter.fetch_add(1, std::memory_order_relaxed);
            runtime.pHeartbeat->last_tick = GetTickCount64();
        }

        // Sleep in small increments to allow immediate reaction to shutdown signals
        for (int i = 0; i < 10 && m_running.load(); ++i) {
            Sleep(100);
        }
    }
}
