# Priority Manager (PMan)

PMan is an automated Windows performance management utility that optimizes process scheduling, resource allocation, and system services to improve responsiveness during gaming and multitasking. It operates entirely in user mode without kernel drivers or permanent system modifications.

## Verified Capabilities

Based on the current implementation, PMan provides:

**Automated Process Classification:** Real-time detection of games, browsers, video players, and launchers using ETW events, window titles, and executable name matching

**Dynamic System Optimization:** Adjusts Win32PrioritySeparation, CPU affinity, I/O priority, GPU priority, and working set limits based on foreground application

**Service Lifecycle Management:** Temporarily suspends Windows Update, BITS, Delivery Optimization, SysMain, and other background services during gaming sessions

**Idle System Enhancement:** Boosts Explorer.exe and DWM.exe responsiveness when the system is idle; parks background processes on last N cores

**Network-Aware Throttling:** Detects unstable network conditions and applies CPU/I/O throttling to background network-bound processes

**Memory Pressure Mitigation:** Purges standby list and trims non-critical processes when RAM utilization exceeds 80% or hard fault rate is high

**Performance Learning:** Builds per-game profiles to determine optimal settings through non-destructive A/B testing

**Stutter Detection:** Monitors frame presentation events via ETW to detect and mitigate performance anomalies

**Crash Protection:** Registry guard process restores original system state if PMan terminates abnormally

## Explicit Non-Goals

PMan does not implement:

- Custom user-defined process rules or profiles
- Real-time kernel-level scheduling
- Network telemetry or cloud-based analytics
- Graphical user interface beyond system tray integration
- Permanent hardware configuration changes

## Safety & Reversibility Guarantees

All modifications are session-scoped and reversible:

- Registry values are restored on clean exit if restore_on_exit is enabled (default)
- A crash-proof registry guard runs as a detached process to monitor for abnormal termination
- Service modifications are temporary; services are resumed when gaming ends
- Process optimizations are reverted on process termination or mode change
- No persistent files are created outside of C:\ProgramData\PriorityMgr
- All operations respect Windows integrity levels and fail gracefully without admin rights

## System Requirements

- **OS:** Windows 10 version 1809 or newer (build 17763+). Hybrid core detection requires Windows 10 2004+.
- **Architecture:** x64 or ARM64
- **Privileges:** Administrative rights required for registry modification, service control, and advanced power management. Falls back to read-only monitoring without elevation.
- **Dependencies:** No runtime dependencies beyond standard Windows APIs

## Installation

PMan installs via a one-time startup task registration:
```
pman.exe --silent
```

Configuration files are created on first run in %ProgramData%\PriorityMgr:

- config.ini - Main configuration
- games.txt - Game executable list
- browsers.txt - Browser executable list
- ignore_processes.txt - System process exclusion list
- custom_launchers.txt - Game launcher definitions

## Usage

**Primary Interface:** System tray icon

Right-click for menu: Live Log, Configuration Editing, Pause/Resume, Exit

Live Log Viewer displays real-time activity with 2000-line circular buffer

Editor detection: Notepad++, VS Code, Sublime Text auto-detected; falls back to elevated Notepad

**Command Line Options:**

- --silent - Run without UI
- --paused - Start in paused state
- --uninstall - Remove startup task and terminate instances
- --guard - Internal use: crash recovery daemon

**Configuration:** Edit INI files in %ProgramData%\PriorityMgr. Changes are applied with 1-second debounce.

## Files and Directories

- **Executable:** Self-contained binary, typically installed to %ProgramFiles%
- **Data:** %ProgramData%\PriorityMgr (logs, configs, profiles)
- **Log:** log.txt with automatic rotation at 5MB
- **Profiles:** profiles.bin - Binary game performance database

## Performance Impact

- **CPU:** ETW callbacks are ring-buffered and rate-limited. Background threads pinned to last cores at lowest priority.
- **Memory:** ~8KB session cache, bounded process tracker maps with hourly cleanup
- **I/O:** Log writes batched to 5-second intervals; async file operations
- **Network:** Connectivity probe every 30s (stable) or 5s (unstable) using ICMP

## Limitations & Caveats

- **ETW Availability:** Some enterprise security software may block private ETW sessions, disabling process detection
- **Admin Rights Required:** Full optimization requires elevation; read-only mode provides limited benefit
- **Fixed Classification:** Cannot define custom process categories; relies on built-in heuristics and lists
- **Windows 10+ Only:** Legacy OS versions lack required APIs for hybrid cores, power throttling, and service control
- **No Multi-User Isolation:** Operates on active console session only; RDP/terminal server scenarios not supported

## Troubleshooting

- **Logs:** Check %ProgramData%\PriorityMgr\log.txt for [ERROR] or [WARN] entries
- **Pause Mode:** Use tray menu "Pause Activity" to isolate issues
- **Clean Start:** Delete config.ini to restore defaults
- **Service Recovery:** Run net start wuauserv and net start BITS manually if left suspended

## Support

No official support channel is implemented. For issues, review logs and configuration files. The system is designed for self-service operation.
