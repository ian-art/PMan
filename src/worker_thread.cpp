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

#include "worker_thread.h"

void WorkerQueue::Start()
{
    m_running.store(true, std::memory_order_release);
    m_thread = std::thread(&WorkerQueue::WorkerLoop, this);
}

void WorkerQueue::Stop()
{
    m_running.store(false, std::memory_order_release);
    m_cv.notify_all();
    if (m_thread.joinable())
        m_thread.join();
}

void WorkerQueue::Push(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_tasks.push_back(std::move(task));
    }
    m_cv.notify_one();
}

void WorkerQueue::WorkerLoop()
{
    while (true)
    {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cv.wait(lk, [this]
            {
                return !m_tasks.empty() || !m_running.load(std::memory_order_acquire);
            });

            if (!m_running.load(std::memory_order_acquire) && m_tasks.empty())
                return;

            if (!m_tasks.empty())
            {
                task = std::move(m_tasks.front());
                m_tasks.pop_front();
            }
        }
        if (task) task();
    }
}
