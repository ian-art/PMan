#ifndef PMAN_SYSINFO_H
#define PMAN_SYSINFO_H

#include "types.h"

// Core detection functions
void PreFlightCheck();
void DetectOSCapabilities();
void DetectHybridCoreSupport();
bool DetectIoPrioritySupport();
bool DetectGameIoPrioritySupport();

#endif // PMAN_SYSINFO_H