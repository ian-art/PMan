# System Architecture

## Overview

PMan is a multi-threaded, event-driven Windows performance manager built around three core asynchronous primitives: ETW (Event Tracing for Windows), IOCP (I/O Completion Ports), and a background worker thread pool. The architecture prioritizes safety, scalability, and minimal system impact through careful resource bounding and privilege-aware operation.

## Component Structure
```
┌─────────────────────────────────────────────────────────────────────┐
│                         PMan Process                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │   Main Thread│  │   ETW Thread │  │  IOCP Thread │               │
│  │  (UI & Msg)  │  │  (Providers) │  │   (Watcher)  │               │
│  └──────┬───────┘  └────────┬─────┘  └──────────┬───┘               │
│         │                   │                   │                   │
│         │  Process Events   │  Config Changes   │                   │
│         └─────────┬─────────┴──────────┬────────┘                   │
│                     │                  │                            │
│              ┌──────▼──────────────────▼───────┐                    │
│              │       IOCP Queue (g_hIocp)      │                    │
│              └──────┬────────────────────────┬─┘                    │
│                     │                        │                      │
│            ┌────────▼────────┐      ┌───────▼────────┐              │
│            │ Policy Worker   │      │ Crash Safety   │              │
│            │ (Single Thread) │      │ Registry Guard │              │
│            └────────┬────────┘      └────────────────┘              │
│                     │                                               │
│            ┌────────▼────────┐                                      │
│            │   Apply Tweaks  │                                      │
│            │  (Rate-Limited) │                                      │
│            └─────────────────┘                                      │
│                                                                     │
│  Background Workers:                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Mem Optimizer│  │ Perf Guardian│  │ Net Monitor  │               │
│  │   (1s loop)  │  │  (2s loop)   │  │ (5-30s loop) │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                     │
│  Global State & Utilities:                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  globals.cpp │  │  logger.cpp  │  │   utils.cpp  │               │
│  │  (State Mgmt)│  │   (Logging)  │  │  (Helpers)   │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                     │
│  Optional/Specialized:                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │   restore.cpp│  │services_watch│  │ static_tweaks│               │
│  │ (Snapshots)  │  │   (Trim)     │  │ (One-time)   │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                     │
│  Network Intelligence:                                              │
│  ┌────────────────┐                                                 │
│  │throttle_mgr.cpp│                                                 │
│  │ (Adaptive QoS) │                                                 │
│  └────────────────┘                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Execution Model

### 1. Event Ingestion Layer

**ETW Thread (EtwThread):** Runs a private real-time ETW session monitoring:

- Process start/end (KernelProcessGuid)
- DXGI/D3D9/D3D10 Present events for frame time tracking
- DPC/ISR latency events

Events are immediately posted to the IOCP queue as IocpJob structures

**Raw Input Thread:** Monitors HID input via RegisterRawInputDevices for user activity detection

**Config Watcher Thread (IocpConfigWatcher):** Uses ReadDirectoryChangesW on %ProgramData%\PriorityMgr to trigger config reload

### 2. Job Queue & Processing

**IOCP Handle (g_hIocp):** Central dispatch queue with 1000-job limit to prevent memory exhaustion

**Job Types:** Policy, Config, PerformanceEmergency

**Single Policy Worker:** Dequeues jobs sequentially to avoid race conditions. Each job triggers:

- Process identity validation (PID + creation time)
- Classification via name lists, window detection, hierarchy inheritance
- Tiered optimization application (affinity, priority, QoS)

### 3. Background Workers

**Memory Optimizer (MemoryOptimizer::RunThread):** 1Hz loop that monitors RAM pressure and triggers standby purge + working set trim when memoryLoad > 80% or hardFaults > 100/sec

**Performance Guardian (PerformanceGuardian::OnPerformanceTick):** 0.5Hz loop analyzing frame history (ETW Present events) to detect stutter (>5% spikes or variance >8ms) and trigger emergency boosts

**Network Monitor (NetworkMonitor::WorkerThread):** Adaptive polling (5s unstable/30s stable) performing ICMP probes to 1.1.1.1/8.8.8.8. Throttles background PIDs when latency >600ms or packet loss detected

**Idle Affinity Manager (IdleAffinityManager::OnIdleStateChanged):** Activates after 30s idle, parks processes on last N cores (respecting foreground app protection)

### 4. State Management

All global state resides in globals.cpp with strict access patterns:

- Atomic flags for single-value state (e.g., g_running, g_sessionLocked)
- SharedMutex for read-heavy sets (e.g., g_games, g_browsers)
- std::mutex for write-heavy maps (e.g., g_processHierarchy)
- SessionSmartCache: Atomic pointer swap for crash-safe PID lock verification

## Thread Safety & Synchronization

| Component            | Synchronization         | Notes                                             |
| -------------------- | ----------------------- | ------------------------------------------------- |
| Configuration Sets   | `std::shared_mutex`     | Read-heavy, updated only on file change           |
| Process Hierarchy    | `std::shared_mutex`     | Hierarchy traversal is read-mostly                |
| Working Set Tracking | `std::mutex`            | Frequent updates during game switches             |
| IOCP Queue           | `std::atomic<int>`      | Lock-free size counter; jobs dequeued under mutex |
| Policy State         | `std::atomic<uint64_t>` | Encoded PID + mode; atomic load/store only        |

## Component Responsibilities

| Module                 | Responsibility                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------- |
| `main.cpp`             | Process lifecycle, threading, UI, command parsing                                   |
| `globals.cpp`          | Global variables, atomic flags, shared state containers                             |
| `logger.cpp`           | Circular buffer logging, log rotation, Live Log Viewer integration                  |
| `utils.cpp`            | String conversion, process enumeration, registry helpers, HTTP client, security checks |
| `policy.cpp`           | Process classification, mode determination, session locking, hierarchy management   |
| `tweaks.cpp`           | Low-level optimization: priority, affinity, QoS, memory, timer resolution           |
| `config.cpp`           | INI parsing, defaults, upgrade handling, process list management                    |
| `events.cpp`           | ETW session management, event routing, DPC latency tracking                         |
| `performance.cpp`      | Frame time analysis, stutter detection, profile learning, session reports           |
| `services.cpp`         | Service enumeration, suspension, resumption with safety whitelist                   |
| `services_watcher.cpp` | Background scanning for idle manual-start services to stop                          |
| `network_monitor.cpp`  | Connectivity probing, bandwidth monitoring, network state detection                 |
| `memory_optimizer.cpp` | RAM pressure detection, standby purge, working set trim                             |
| `idle_affinity.cpp`    | Background process parking during system idle                                       |
| `explorer_booster.cpp` | Explorer/DWM boosting when system idle and no active game                           |
| `input_guardian.cpp`   | Windows key blocking, input latency monitoring, foreground boosting                 |
| `sysinfo.cpp`          | CPU topology detection (Intel P/E, AMD CCD), capability detection                   |
| `session_cache.cpp`    | Immutable process identity for session lock validation                              |
| `static_tweaks.cpp`    | One-time system optimization registry tweaks (manual trigger only)                  |
| `restore.cpp`          | System restore point creation on first run (admin only)                             |
| `throttle_manager.cpp` | Network-based adaptive CPU/I/O throttling using Job Objects                         |
| `types.h/constants.h`  | Type definitions, GUIDs, and configuration constants                                |

## Configuration & Data Flow

**Initial Load:** LoadConfig() on startup parses config.ini into global sets

**Runtime Updates:** Config watcher detects file change, sets g_reloadNow, background worker reloads after 250ms debounce

**Profile Persistence:** PerformanceGuardian serializes learned profiles to profiles.bin with magic header 0x504D414E

**Logging:** Circular buffer (2000 lines) flushed to %ProgramData%\PriorityMgr\log.txt every 5s or when Live Log Viewer opens

## Error Handling & Resilience

**PID Reuse:** Every operation validates (PID, creationTime) pair via GetProcessTimes

**Access Denied:** Non-admin operations skip registry writes with logged warnings

**ETW Failure:** Watchdog thread auto-restarts ETW session up to 3 times

**Service Deadlock:** 5s timeout + retry loop for service control operations

**Registry Corruption:** RunRegistryGuard monitors main process exit and restores Win32PrioritySeparation + power plan

**Memory Exhaustion:** Bounded containers (2000 log lines, 1000 process tracker entries) with hourly GC

## Execution Guarantees

**No Blocking in Hot Path:** ETW callback posts to IOCP and returns immediately; no file I/O or registry access

**Bounded Latency:** Policy worker processes jobs sequentially; max queue size 1000 prevents unbounded growth

**Graceful Degradation:** Features silently disable if APIs unavailable (legacy OS, missing permissions)

**Clean Shutdown:** RAII handles, thread joining, registry restoration on WM_DESTROY

## Safety Mechanisms

### Registry Anti-Hammering
To prevent registry corruption or high CPU usage from constant writes:
- **Mechanism:** `RegWriteDwordCached` checks the current registry value first.
- **Logic:** `if (current == new) return; else Write();`
- **Benefit:** Reduces registry I/O by 99% during stable states.

### Service Snapshots
PMan never "guesses" what a service's priority was.
1. **Snapshot:** Before optimizing, PMan records the service's *actual* Affinity and Priority.
2. **Restore:** On game exit, it applies the recorded values.
3. **Fail-Safe:** If a service crashes or restarts, it is removed from the management list to prevent applying invalid state.

### Intelligent RAM Cleaning
- **Old Behavior:** Purged Standby List every N minutes.
- **New Behavior:** "Emergency Only." Checks `GlobalMemoryStatusEx`.
- **Condition:** Only purges if Physical RAM load > 90%.

## Directory Structure
- `src/`: Core C++ implementation.
- `include/`: Header files and internal API abstractions.
- `docs/`: Architecture and Contribution guides.