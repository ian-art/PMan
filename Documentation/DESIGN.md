# Design Rationale & Implementation Trade-offs

## Core Philosophy: Observability Without Intrusiveness

The design centers on user-mode observability of system behavior via ETW and Win32 APIs. This choice explicitly avoids kernel drivers to maintain system stability, compatibility with anti-cheat, and easy uninstallation. All optimizations are standard Windows primitives (priority classes, affinity masks, registry keys) that are reversible and well-documented.

## Event-Driven vs. Polling Trade-offs

**Decision:** Hybrid model

**ETW for Process/Graphics:** Real-time notifications for process start/end and DXGI Present events provide immediate response with ~1ms overhead. Ring buffer in DPC callback avoids heap allocation.

**Polling for Metrics:** CPU load, memory pressure, and network stability use timed loops (1s, 10s, 30s) because:

- No ETW provider exists for memory pressure notifications
- Network state requires active probing (ICMP)
- Polling allows rate-limiting and hysteresis to prevent thrashing

**Trade-off:** Slightly higher baseline CPU usage (~0.1% on idle) vs. immediate reaction to all events.

## Safety-First Process Classification

**Hierarchy of Checks (in order of precedence):**

1. **Ignored Process List:** System processes (csrss, lsass, etc.) are hard-excluded first to prevent OS instability
2. **Anti-Cheat Detection:** Explicitly avoids touching known anti-cheat processes; disables risky features if detected
3. **Launcher Tier:** Custom launchers get conservative settings (IDLE priority, no hard affinity) to prevent game launch interference
4. **Session Lock:** Once a game is detected, no mode changes are allowed until it exits (PID validated via creation time)
5. **Window Heuristics:** Final fallback uses window title/class matching

**Rationale:** Each layer protects against false positives. The cost of missing a game is lower than misclassifying a system process.

## Session Lock & PID Reuse Protection

**Problem:** PID reuse can cause a new process to inherit optimizations meant for a dead game, or vice versa.

**Solution:** SessionSmartCache stores (PID, creationTime) tuple atomically. Every operation validates identity before applying changes. The cache is immutable after creation and swapped with std::atomic_exchange to avoid torn reads.

**Trade-off:** OpenProcess() call per validation adds ~100us latency to each policy decision, but prevents catastrophic misapplication.

## Adaptive Learning vs. Static Rules

**Design:** Game profiles use voting rather than hard thresholds:

- Each optimization (I/O priority, core pinning, memory compression) gets a vote count (0-5)
- After 30s A/B test phases, vote increments if variance improves >10%
- Feature enabled if vote >= 2

**Rationale:** Non-destructive experimentation. A failed test reverts automatically after 30s. Votes decay slowly, allowing adaptation to driver/OS updates.

## Resource Bounding

**Memory:** All unbounded containers are capped:

- Log buffer: 2000 lines
- Process trackers: 1000 entries (GC'd hourly)
- Hierarchy map: 2000 nodes (cleared on overflow)
- IOCP queue: 1000 jobs (new jobs dropped if full)

**CPU:** Background threads pinned to last physical cores with THREAD_PRIORITY_LOWEST. ETW thread runs at normal priority to prevent event loss.

**Rationale:** Prevents PMan itself from becoming a resource hog during extended uptime.

## Intel P/E vs. AMD 3D V-Cache Handling

**Intel:** Uses SetProcessDefaultCpuSets API (Windows 10 2004+) to pin games to P-cores (EfficiencyClass 0). E-cores remain for background tasks.

**AMD:** Detects L3 cache topology. For 3D V-Cache CPUs, identifies CCD0 (cache-equipped) vs. CCD1+ and pins games to CCD0 cores only. This leverages the 96MB L3 cache advantage.

**Fallback:** If APIs unavailable or on homogeneous CPUs, uses legacy affinity partitioning (reserve last N cores for background).

## Service Suspension Safety

**Problem:** Suspending critical services (RPC, Power) can brick the OS.

**Solution:** Multi-layer whitelist:

- **Level 0:** Hard-coded critical list (RpcSs, Power, etc.) - never touched
- **Level 1:** Operational whitelist (BITS, wuauserv, dosvc) - only these are eligible
- **Dependency Check:** EnumDependentServicesW verifies no active dependents before suspension

**Trade-off:** More conservative than aggressive "game boosters" but guarantees system stability.

## Registry Guard Pattern

**Mechanism:** On start, launches pman.exe --guard <pid> <creationTime> <regValue> as a detached process. This process:

1. Waits on the main process handle with SYNCHRONIZE
2. On exit, reads current registry value
3. If mismatched, restores original value
4. Also verifies power plan and resumes suspended services

**Rationale:** Survives crashes, kills, or power loss. No reliance on destructors or graceful shutdown.

## Configuration Upgrades

**Design:** Config version stored in [meta] section. On load mismatch:

1. Creates backup with .old extension
2. Injects current game/browser lists into new schema
3. Writes upgraded config atomically
4. Reloads from new file

**Rationale:** Preserves user data across feature updates without migration scripts.

## Network Throttling Hysteresis

**Problem:** Flapping between STABLE/UNSTABLE causes priority oscillation.

**Solution:** 10-second hold-off timer after state change. Background apps remain throttled for minimum duration, smoothing jitter.

## Log Viewer Overhead

**Trade-off:** Live Log Viewer (FindWindowW(L"PManLogViewer")) triggers async flush. This adds disk I/O but only when viewer is open. Circular buffer prevents unbounded memory growth.

## No Telemetry Principle

**Verification:** Code search shows:

- No HTTP calls except to raw.githubusercontent.com for version checks
- No data collection, metrics upload, or usage tracking
- Logs are local only with ACL restrictions

**Rationale:** System-level tools must be auditable and privacy-respecting. Update checks are opt-in via tray menu.