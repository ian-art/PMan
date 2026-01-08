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

#ifndef PMAN_SERVICES_H
#define PMAN_SERVICES_H

#include "types.h"
#include <windows.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>

// Enhanced Service Management Class
class WindowsServiceManager
{
public:
    struct ServiceState
    {
        std::wstring name;
        SC_HANDLE handle;
        ServiceAction action;
        DWORD originalState;
        bool isDisabled;
        
        ServiceState() : handle(nullptr), action(ServiceAction::None), 
                        originalState(SERVICE_STOPPED), isDisabled(false) {}
    };
    
private:
    SC_HANDLE m_scManager;
	std::unordered_map<std::wstring, ServiceState> m_services;
    std::mutex m_mutex;
    std::atomic<bool> m_anythingSuspended;
    
public:
    WindowsServiceManager() : m_scManager(nullptr), m_anythingSuspended(false) {}
    
    ~WindowsServiceManager();
    
    bool Initialize();
    bool AddService(const std::wstring& serviceName, DWORD accessRights);
    bool SuspendService(const std::wstring& serviceName);
    bool ResumeService(const std::wstring& serviceName);
    bool SuspendAll();
    void ResumeAll();
	bool IsAnythingSuspended() const;
    void Cleanup();

	// Metrics
    double GetBitsBandwidthMBps() const;
    void UpdateBitsMetrics();

private:
    mutable std::mutex m_metricsMtx;
    mutable double m_lastBitsBandwidth = 0.0;
    mutable uint64_t m_lastBandwidthQuery = 0;
};

// Global helper functions for service management logic
void SuspendBackgroundServices();
void ResumeBackgroundServices();

// BITS Bandwidth Monitor
double GetBitsBandwidth();

#endif // PMAN_SERVICES_H
