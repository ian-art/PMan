#ifndef PMAN_POLICY_H
#define PMAN_POLICY_H

#include "types.h"

int DetectWindowType(HWND hwnd);
void CheckAndReleaseSessionLock();
bool ShouldIgnoreDueToSessionLock(int detectedMode, DWORD pid);
bool IsPolicyChangeAllowed(int newMode);
void EvaluateAndSetPolicy(DWORD pid, HWND hwnd = nullptr);

#endif // PMAN_POLICY_H