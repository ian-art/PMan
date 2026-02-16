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

#ifndef PMAN_CRASH_REPORTER_H
#define PMAN_CRASH_REPORTER_H

#include "types.h"

namespace CrashReporter {

    // --- Breadcrumbs (Flight Recorder) ---
    // POD structure for raw memory dump compatibility
    struct BreadcrumbEntry {
        uint32_t fileId;
        uint16_t line;
        uint32_t eventId;
        uint64_t timestamp;
    };

    // Initialize the crash reporter. 
    // Must be called as early as possible in main().
    void Initialize();

    // Record a breadcrumb (Lock-free, extremely fast)
    void LogBreadcrumb(uint32_t fileId, uint16_t line, uint32_t eventId);

    // Force a crash dump manually (for testing or watchdog trigger)
    void TriggerManualDump();

    // SEH Filter for __try/__except blocks
    // Usage: __except(CrashReporter::SehFilter(GetExceptionInformation()))
    LONG WINAPI SehFilter(PEXCEPTION_POINTERS pExceptionInfo);
}

// Convenience Macro for Breadcrumbs
// Usage: CRASH_TRACE(101); 
// Note: Assign unique File IDs to your CPP files if needed.
#define CRASH_TRACE(eventId) \
    CrashReporter::LogBreadcrumb(0, __LINE__, eventId)

#endif // PMAN_CRASH_REPORTER_H
