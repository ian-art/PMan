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

#pragma once
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

class WorkerQueue
{
public:
    WorkerQueue()  = default;
    ~WorkerQueue() { if (m_running.load(std::memory_order_acquire)) Stop(); }

    WorkerQueue(const WorkerQueue&)            = delete;
    WorkerQueue& operator=(const WorkerQueue&) = delete;
    WorkerQueue(WorkerQueue&&)                 = delete;
    WorkerQueue& operator=(WorkerQueue&&)      = delete;

    // Starts the dedicated background worker thread. Call exactly once before Push().
    void Start();

    // Drains remaining tasks then joins. Blocks until thread exits.
    void Stop();

    // Thread-safe. Posts a task. Safe from any TU via PManContext::Get().workerQueue.Push(...).
    void Push(std::function<void()> task);

    // Returns the OS native thread handle so the caller can set affinity/priority
    // after Start() — mirrors the PinBackgroundThread pattern used for other threads.
    std::thread::native_handle_type NativeHandle() noexcept { return m_thread.native_handle(); }

private:
    void WorkerLoop();

    std::thread                        m_thread;
    std::mutex                         m_mtx;
    std::deque<std::function<void()>>  m_tasks;
    std::condition_variable            m_cv;
    std::atomic<bool>                  m_running{false}; // §2: atomic — shared across threads
};
