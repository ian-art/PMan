# Changelog

All notable changes to **PMan** will be documented in this file.

This project follows a **baseline-first documentation model**. No historical version data exists prior to the initial public baseline listed below.

---

## [Initial Public Baseline] — 2025-01-16

This release represents the **first formal documentation and feature baseline** for PMan.

### Added

- Complete system architecture and performance management suite
- ETW-based process and graphics event monitoring
- IOCP-driven asynchronous policy engine
- Multi-threaded background workers:
  - Memory management
  - Network optimization
  - Performance monitoring
- Session-scoped optimization with crash-proof registry guard
- Adaptive learning system for game-specific performance profiles
- Idle CPU affinity parking with Explorer and DWM priority boosting
- Network-aware adaptive throttling mechanisms
- Stutter detection with emergency performance boost handling
- System tray user interface with live log viewer
- Configuration files with automatic upgrade and migration handling
- Safety mechanisms:
  - PID reuse protection
  - Anti-cheat environment detection
  - Critical Windows service whitelist enforcement

## [3.6.0] — 2026-01-20

**Architecture 2.0 (The "Safety First" Update)**
This release focuses on eliminating technical debt, enforcing thread safety, and ensuring crash resilience.

### Architecture & Safety
- **Global State Decomposition:** Replaced loose global variables with a unified `PManContext` singleton.
- **Thread Safety:** Eliminated all unsafe `std::thread::detach()` calls. Replaced with managed `std::thread` members in `InputGuardian` and `ServiceWatcher`.
- **Atomic Session Cache:** Fixed "Use-After-Free" race conditions in the session cache using `std::atomic<std::shared_ptr>`.
- **RAII Enforcement:** Replaced raw `SC_HANDLE` management with `std::unique_ptr` and custom deleters to prevent handle leaks.

### New Features
- **Crash-Proof Registry Guard:** A new Watchdog process monitors the application. If PMan is killed forcefully (e.g., Task Manager), critical system settings (network throttling, priority separation) are automatically reverted to defaults.
- **Transaction Safety:** Services suspended by Game Mode are now guaranteed to auto-resume on exit, even during a crash.

### Improvements
- **Input Guardian:** Refactored to run on a managed worker thread, preventing zombie thread accumulation during DWM scanning.
- **Logger:** Fixed race conditions in the logging queue during shutdown.

---

### Technical Foundation

- **Target Operating Systems**
  - Windows 10 build 17763 and later
  - Windows 11

- **Architecture**
  - x64
  - ARM64

- **Implementation**
  - Language: C++17
  - API: Win32

- **System Impact**
  - No kernel drivers
  - No permanent system modifications
  - No telemetry collection
  - No network activity beyond version checking
