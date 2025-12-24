#include "logger.h"
#include "types.h" // For Windows definitions if needed
#include <windows.h>
#include <sddl.h>   // Required for security descriptor string conversion
#include <aclapi.h> // Required for security functions
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
        
        // Fix 4.1: Secure Directory Creation (Admins: Full, Users: Read-Only)
        if (!std::filesystem::exists(dir))
        {
            PSECURITY_DESCRIPTOR pSD = nullptr;
            // D:DACL, A:Allow, GA:GenericAll (Admins), GR:GenericRead (Users)
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:(A;OICI;GA;;;BA)(A;OICI;GR;;;BU)", 
                    SDDL_REVISION_1, &pSD, nullptr))
            {
                SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
                CreateDirectoryW(dir.c_str(), &sa);
                LocalFree(pSD);
            }
            else
            {
                // Fallback if security descriptor fails
                std::filesystem::create_directories(dir);
            }
        }

       std::ofstream log(dir / L"log.txt", std::ios::app);
        if (log)
        {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            
            // Safer buffer handling for timestamp
            const size_t TIMEBUF_SIZE = 32;
            char timebuf[TIMEBUF_SIZE] = {0};
            struct tm timeinfo;
            
            if (localtime_s(&timeinfo, &t) == 0)
            {
                // Use strftime with explicit buffer size control
                if (std::strftime(timebuf, TIMEBUF_SIZE, "%Y-%m-%d %H:%M:%S", &timeinfo) > 0)
                {
                    log << timebuf << "  " << msg << std::endl;
                }
                else
                {
                    // Handle formatting error gracefully
                    log << "[Timestamp Error] " << msg << std::endl;
                }
            }
            else
            {
                // Fallback if time conversion fails
                log << msg << std::endl;
            }
        }
    }
    catch (const std::exception&) 
    { 
        // Silent in background mode - no console output
    }
}