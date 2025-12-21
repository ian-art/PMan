#include "logger.h"
#include "types.h" // For Windows definitions if needed
#include <windows.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>

static std::mutex g_logMtx;

std::filesystem::path GetLogPath()
{
    wchar_t* programData = nullptr;
    size_t len = 0;
    if (_wdupenv_s(&programData, &len, L"ProgramData") == 0 && programData)
    {
        std::filesystem::path result = std::filesystem::path(programData) / L"PriorityMgr";
        free(programData);
        return result;
    }
    return std::filesystem::path(L"C:\\ProgramData\\PriorityMgr");
}

void Log(const std::string& msg)
{
    std::lock_guard lg(g_logMtx);
    try
    {
        std::filesystem::path dir = GetLogPath();
        std::filesystem::create_directories(dir);
        std::ofstream log(dir / L"log.txt", std::ios::app);
        if (log)
        {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char timebuf[32];
            struct tm timeinfo;
            if (localtime_s(&timeinfo, &t) == 0 && 
                std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &timeinfo))
            {
                log << timebuf << "  " << msg << std::endl;
            }
        }
    }
    catch (const std::exception&) 
    { 
        // Silent in background mode - no console output
    }
}