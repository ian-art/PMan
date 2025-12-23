#ifndef PMAN_BUILD_OPTIONS_H
#define PMAN_BUILD_OPTIONS_H

// Thread safety debugging options
#ifdef _DEBUG
    // Enable thread safety annotations for Clang/MSVC
    #if defined(__clang__) || defined(_MSC_VER)
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
#endif

#endif // PMAN_BUILD_OPTIONS_H