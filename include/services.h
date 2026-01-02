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