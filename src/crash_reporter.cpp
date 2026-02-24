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

#include "crash_reporter.h"
#include <dbghelp.h>
#include <atomic>
#include <strsafe.h>

#pragma comment(lib, "Dbghelp.lib")

namespace CrashReporter {

    // --- Configuration ---
    static const wchar_t* DUMP_FOLDER = L"C:\\ProgramData\\PriorityMgr\\Dumps";
    static const wchar_t* MARKER_FILE = L"C:\\ProgramData\\PriorityMgr\\crash_marker.dat";
    static const DWORD STORM_WINDOW_MS = 60000; // 60 seconds
    static const DWORD MAX_CRASHES_IN_WINDOW = 3;

    // --- Breadcrumbs Data ---
    // Must be global to ensure visibility in raw memory
    struct BreadcrumbBuffer {
        static constexpr size_t COUNT = 128; // Power of two
        BreadcrumbEntry entries[COUNT];
        // Index is managed externally to keep struct POD
    };

    // Explicitly exported to prevent linker optimization
    __declspec(dllexport) BreadcrumbBuffer g_breadcrumbs = {};
    static std::atomic<uint32_t> g_breadcrumbIndex{ 0 };

    // --- Interlocks ---
    static LONG g_DumpInProgress = 0;

    // --- Forward Declarations ---
    static void WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo);
    static bool CheckDumpStorm();

    // --- Breadcrumb Implementation ---
    void LogBreadcrumb(uint32_t fileId, uint16_t line, uint32_t eventId) {
        // Atomic reservation of slot
        uint32_t idx = g_breadcrumbIndex.fetch_add(1, std::memory_order_relaxed) & (BreadcrumbBuffer::COUNT - 1);
        
        // Write to buffer (Race condition on overwrite is acceptable for log)
        BreadcrumbEntry& entry = g_breadcrumbs.entries[idx];
        entry.fileId = fileId;
        entry.line = line;
        entry.eventId = eventId;
        
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        entry.timestamp = qpc.QuadPart;
    }

    // --- Crash Handler Implementation ---

    // The core dumper function
    static void WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo) {
        // Dump Storm Protection
        if (!CheckDumpStorm()) {
            return; // Too many crashes, abort to prevent disk filling
        }

        // Generate filename: PMan_vX_YYYYMMDD_HHMMSS.dmp
        wchar_t path[MAX_PATH];
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        // Ensure directory exists
        CreateDirectoryW(DUMP_FOLDER, nullptr);

        StringCchPrintfW(path, MAX_PATH, L"%s\\PMan_Crash_%04d%02d%02d_%02d%02d%02d.dmp",
            DUMP_FOLDER,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return;

        MINIDUMP_EXCEPTION_INFORMATION mei;
        mei.ThreadId = GetCurrentThreadId();
        mei.ExceptionPointers = pExceptionInfo;
        mei.ClientPointers = FALSE;

        // Explicit Breadcrumb Inclusion
        // This fixes the "Magic" Breadcrumb Flaw
        MINIDUMP_USER_STREAM userStream;
        userStream.Type = LastReservedStream + 1; // Custom stream
        userStream.Buffer = (void*)&g_breadcrumbs;
        userStream.BufferSize = sizeof(g_breadcrumbs);

        MINIDUMP_USER_STREAM_INFORMATION userStreamInfo;
        userStreamInfo.UserStreamCount = 1;
        userStreamInfo.UserStreamArray = &userStream;

        // Minidump Type Selection
        DWORD flags = MiniDumpWithIndirectlyReferencedMemory |
                      MiniDumpScanMemory |
                      MiniDumpWithThreadInfo |
                      MiniDumpWithUnloadedModules;

        // Write the dump
        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hFile,
            (MINIDUMP_TYPE)flags,
            &mei,
            &userStreamInfo, // Pass our breadcrumbs here
            nullptr
        );

        CloseHandle(hFile);
    }

    // Vectored Exception Handler (VEH)
    // Catches exceptions before the frame is unwound
    static LONG WINAPI PManVectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;

        // VEH Exception Flood Protection
        // Filter out benign C++ exceptions (0xE06D7363) and debugger noise
        if (code == 0xE06D7363 || // C++ Exception (std::runtime_error, etc)
            code == 0xE0434352 || // CLR Exception
            code == 0x40010006 || // OutputDebugString
            code == 0x4001000A)   // OutputDebugStringW
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Filter: Only handle FATAL hardware exceptions
        bool isFatal = false;
        if (pExceptionInfo->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
            isFatal = true;
        }
        
        switch (code) {
            case EXCEPTION_ACCESS_VIOLATION:
            case EXCEPTION_ILLEGAL_INSTRUCTION:
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
            case EXCEPTION_STACK_OVERFLOW:
            case EXCEPTION_PRIV_INSTRUCTION:
                isFatal = true;
                break;
        }

        if (!isFatal) return EXCEPTION_CONTINUE_SEARCH;

        // DbgHelp Thread Safety & Reentrancy
        if (InterlockedCompareExchange(&g_DumpInProgress, 1, 0) == 0) {
            
            // Stack Overflow Recovery (Minimal)
            // If stack is blown, we cannot do much, but we try to reset for the dump
            if (code == EXCEPTION_STACK_OVERFLOW) {
                // _resetstkoflw(); // requires malloc.h, often unsafe if heap is corrupt
                // Strategy: Do nothing, rely on pre-allocated stack of this thread or fail.
            }

            WriteCrashDump(pExceptionInfo);
            
            // Terminate immediately after dump
            TerminateProcess(GetCurrentProcess(), code);
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if we are crashing too frequently (Dump Storm)
    static bool CheckDumpStorm() {
        // Use Win32 API only - no CRT, no heap allocation
        HANDLE hFile = CreateFileW(MARKER_FILE, GENERIC_READ, 0, NULL, 
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        struct CrashMarker {
            DWORD crash_count;
            ULONGLONG last_crash_time;
        } marker = { 0, 0 };

        bool allowDump = true;
        ULONGLONG now = GetTickCount64();

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesRead = 0;
            CrashMarker tempMarker = { 0, 0 };
            if (ReadFile(hFile, &tempMarker, sizeof(tempMarker), &bytesRead, NULL) && bytesRead == sizeof(tempMarker)) {
                marker = tempMarker;
                if (now - marker.last_crash_time < STORM_WINDOW_MS) {
                    marker.crash_count++;
                } else {
                    marker.crash_count = 1;
                }
            } else {
                marker.crash_count = 1;
            }
            CloseHandle(hFile);
        } else {
            marker.crash_count = 1;
        }

        marker.last_crash_time = now;

        if (marker.crash_count > MAX_CRASHES_IN_WINDOW) {
            allowDump = false; // Stop writing dumps
        }

        // Update marker
        hFile = CreateFileW(MARKER_FILE, GENERIC_WRITE, 0, NULL, 
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten = 0;
            WriteFile(hFile, &marker, sizeof(marker), &bytesWritten, NULL);
            CloseHandle(hFile);
        }

        return allowDump;
    }

    // SEH Filter Implementation
    LONG WINAPI SehFilter(PEXCEPTION_POINTERS pExceptionInfo) {
        // Same logic as VEH, but specifically for the __except block
        // Guaranteed to run if the exception reaches the main loop wrapper
        if (InterlockedCompareExchange(&g_DumpInProgress, 1, 0) == 0) {
            WriteCrashDump(pExceptionInfo);
            TerminateProcess(GetCurrentProcess(), pExceptionInfo->ExceptionRecord->ExceptionCode);
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }

    void Initialize() {
        // [FIX] Idempotency check to prevent duplicate handlers
        static bool s_initialized = false;
        if (s_initialized) return;
        s_initialized = true;

        // Create dump directory
        CreateDirectoryW(L"C:\\ProgramData\\PriorityMgr", nullptr);
        CreateDirectoryW(DUMP_FOLDER, nullptr);

        // Register Vectored Exception Handler (First response)
        AddVectoredExceptionHandler(1, PManVectoredHandler);
        
        // Register Unhandled Exception Filter (Last resort)
        SetUnhandledExceptionFilter([](PEXCEPTION_POINTERS pExceptionInfo) -> LONG {
            // Re-use logic, ensuring only one runs via g_DumpInProgress
            PManVectoredHandler(pExceptionInfo); 
            return EXCEPTION_EXECUTE_HANDLER;
        });
    }

    void TriggerManualDump() {
        // Raise a non-continuable Access Violation to trigger the VEH dump path
        RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    }
}
