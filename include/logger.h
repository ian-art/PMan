#ifndef PMAN_LOGGER_H
#define PMAN_LOGGER_H

#include <string>
#include <filesystem>

// Log a message to the global log file
void Log(const std::string& msg);

// Get the path to the log directory
std::filesystem::path GetLogPath();

#endif // PMAN_LOGGER_H