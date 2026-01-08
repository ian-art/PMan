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

#ifndef PMAN_BUILD_OPTIONS_H
#define PMAN_BUILD_OPTIONS_H

// Thread safety debugging options
#ifdef _DEBUG
    // Enable thread safety annotations for Clang/MSVC
    // Fix: MSVC does not support __attribute__ syntax
    #if defined(__clang__)
        #define THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
    #else
        #define THREAD_ANNOTATION_ATTRIBUTE__(x)
    #endif
    
    #define GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))
    #define REQUIRES(...) THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))
    #define ACQUIRE(...) THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))
    #define RELEASE(...) THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))
    
    // Enable thread sanitizer if available
    #if defined(__has_feature)
        #if __has_feature(thread_sanitizer)
            #define THREAD_SANITIZER_ENABLED 1
        #endif
    #endif
#else
    // Release build: disable annotations
    #define GUARDED_BY(x)
    #define REQUIRES(...)
    #define ACQUIRE(...)
    #define RELEASE(...)
    #define THREAD_SANITIZER_ENABLED 0
#endif

// Compiler-specific thread sanitizer pragmas
#if defined(_MSC_VER) && _MSC_VER >= 1920
    #pragma warning(push)
    #pragma warning(disable: 28251) // Inconsistent annotation warning
	#ifdef _DEBUG
        // MSVC thread sanitizer (available in VS 2019+)
        #pragma comment(linker, "/include:__scrt_initialize_winrt")
    #endif
    
    #pragma warning(pop)
#endif

#endif // PMAN_BUILD_OPTIONS_H
