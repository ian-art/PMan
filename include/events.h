#ifndef PMAN_EVENTS_H
#define PMAN_EVENTS_H

#include "types.h"

// Events and Threads
void EtwThread();
void IocpConfigWatcher();
void AntiInterferenceWatchdog();
void RegisterPowerNotifications(HWND hwnd);
void UnregisterPowerNotifications();
void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD evt, HWND hwnd, LONG, LONG, DWORD, DWORD);

// Control & Shutdown
bool CheckForShutdownSignal();
void PerformGracefulShutdown();
void StopEtwSession();
void WaitForThreads(DWORD timeoutMs = 5000);
void PostShutdown();
bool PostIocp(JobType t, DWORD pid = 0, HWND hwnd = nullptr);

#endif // PMAN_EVENTS_H