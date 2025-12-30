#ifndef PMAN_EXPLORER_BOOSTER_H
#define PMAN_EXPLORER_BOOSTER_H

#include "types.h"
#include "utils.h" // For UniqueHandle
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <vector>

enum class ExplorerBoostState : uint8_t {
    Default,           // No boosts applied (baseline)
    IdleBoosted,       // Full boosts active (system idle)
    LockedOut          // Game/browser active (strictly no boosts)
};

struct ShellInstance {
    ProcessIdentity identity;
    ExplorerBoostState state;
    uint64_t lastBoostTimeMs;
    UniqueHandle handle;  // RAII handle management
};

struct ExplorerConfig {
    bool enabled = true;
    uint32_t idleThresholdMs = 15000;
    bool boostDwm = true;
    bool disablePowerThrottling = true;
    bool boostIoPriority = false;
    bool preventShellPaging = true;
    uint32_t scanIntervalMs = 5000;
    bool debugLogging = false;
};

class ExplorerBooster {
public:
    // Lifecycle
    void Initialize();
    void Shutdown();
    void OnTick(); // Called every loop iteration
    
    // Configuration
    void UpdateConfig(const ExplorerConfig& cfg);

    // Event handlers
    void OnGameStart(DWORD gamePid); // Pre-emptive revert
    void OnGameStop();
    void OnBrowserStart(DWORD browserPid);
    void OnUserActivity(); // Called from raw input
    
    // State queries
    bool IsBoostActive() const { return m_active; }
    bool IsIdle() const { return m_currentState == ExplorerBoostState::IdleBoosted; }
    uint64_t GetLastUserActivity() const { return m_lastUserActivityMs.load(); }
    uint32_t GetIdleThreshold() const { return m_config.idleThresholdMs; }

private:
    std::atomic<bool> m_active{false};
    std::atomic<ExplorerBoostState> m_currentState{ExplorerBoostState::Default};
    std::unordered_map<DWORD, ShellInstance> m_instances;
    std::mutex m_mtx;
    
    // Configuration
    ExplorerConfig m_config;
    
// State tracking
    std::atomic<uint64_t> m_lastUserActivityMs{0};
	std::atomic<uint64_t> m_lastScanMs{0};
    std::atomic<bool> m_gameOrBrowserActive{false};
    std::atomic<bool> m_isGameSession{false}; // Track if the active session is a Game (true) or Browser (false)
    uint32_t m_currentPollIntervalMs{2000};  // Adaptive polling
    
    // Worker methods
    void ScanShellProcesses();
    void UpdateBoostState();
    void ApplyBoosts(DWORD pid, ExplorerBoostState state);
    void RevertBoosts(DWORD pid);
    bool ShouldBoostNow() const;
    void EnforceMemoryGuard(DWORD pid);
    void ReleaseMemoryGuard(DWORD pid);
    DWORD GetDwmProcessId() const;
    std::vector<DWORD> GetAllShellPIDs() const;
    bool EnableDebugPrivilege();
    
    // Logging
    void LogState(const char* action, DWORD pid = 0) const;
    const char* StateToString(ExplorerBoostState state) const;
};

// Global instance
extern ExplorerBooster g_explorerBooster;

#endif // PMAN_EXPLORER_BOOSTER_H