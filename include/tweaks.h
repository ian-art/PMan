#ifndef PMAN_TWEAKS_H
#define PMAN_TWEAKS_H

#include <windows.h>

// Core optimization functions
void IntelligentRamClean();
bool SetPrioritySeparation(DWORD val);
void SetHybridCoreAffinity(DWORD pid, int mode);
void SetAmd3DVCacheAffinity(DWORD pid, int mode);
void SetProcessIoPriority(DWORD pid, int mode);
void SetNetworkQoS(int mode);
void SetMemoryCompression(int mode);
void SetGpuPriority(DWORD pid, int mode);
void SetTimerResolution(int mode);
void SetProcessAffinity(DWORD pid, int mode);
void SetWorkingSetLimits(DWORD pid, int mode);
void OptimizeDpcIsrLatency(DWORD pid, int mode);
void CleanupProcessState(DWORD pid);
void SetTimerCoalescingControl(int mode);

// Memory pressure check
bool IsUnderMemoryPressure();

#endif // PMAN_TWEAKS_H