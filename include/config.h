#ifndef PMAN_CONFIG_H
#define PMAN_CONFIG_H
#include <filesystem>

void LoadConfig();
bool CreateDefaultConfig(const std::filesystem::path& configPath);

#endif // PMAN_CONFIG_H
