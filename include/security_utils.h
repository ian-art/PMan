/*
 * This file is part of Priority Manager (PMan).
 *
 * Copyright (c) 2025 Ian Anthony R. Tancinco
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef PMAN_SECURITY_UTILS_H
#define PMAN_SECURITY_UTILS_H

#include <windows.h>
#include <string>

namespace SecurityUtils {
    // The Watchtower
    // Detects if a process is a "Proxy Launch" (User script hiding behind System parent)
    // Heuristic: Parent is Infrastructure (WMI, Svchost) BUT Child is User Land.
    bool IsProxyLaunch(DWORD pid);
    
    // Helper: Checks if a Token belongs to SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
    bool IsSystemOrService(HANDLE hToken);

    // [PATCH] Trojan Defense: Verify Authenticode Signature
    bool IsProcessTrusted(DWORD pid);
}

#endif // PMAN_SECURITY_UTILS_H
