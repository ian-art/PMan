# Changelog

All notable changes to **PMan** will be documented in this file.

This project follows a **baseline-first documentation model**. No historical version data exists prior to the initial public baseline listed below.

---
## [6.0.0] — 2026-02-11

**The "Titanium" Update**
A complete architectural rewrite focusing on security, integrity, and isolation. PMan has transitioned from a standalone utility to a **Secure System Service**.

### 🔒 The Secure Core
- **Client-Server Split:** Separated the GUI (Viewer) from the Service (Worker). Communication is now handled via secure Named Pipes (`\\.\pipe\PManSecureInterface`).
- **RBAC Enforcement:** The Service now strictly enforces Role-Based Access Control. Only Administrators can alter the Neural Configuration; Standard Users are restricted to Read-Only access.
- **Binary Configuration:** Deprecated `json/ini` text files in favor of `config.dat`—a binary format encrypted via **DPAPI (CRYPTPROTECT_SYSTEM)**.
- **Tamper Protection:** Added HMAC-SHA256 signature verification and Monotonic Versioning to the config header to prevent "Rollback Attacks" and external tampering.

### 👁️ Watchtower Heuristics
- **Anti-Proxy Detection:** Implemented deep token analysis to detect malware hiding behind legitimate system parents like `WmiPrvSE.exe` or `Task Scheduler`. These "Proxy Launches" are now automatically jailed and throttled.
- **No-Verify Cleanup:** Removed the legacy `WinVerifyTrust` loop, replacing slow signature checks with the new, faster Token Heuristics.

### 🛠️ Technical Changes
- **IPC Protocol:** Defined a strict JSON command protocol (`SET_CONFIG`, `GET_STATUS`) with server-side validation.
- **Memory Hardening:** The Service now actively rejects path traversal (`..`) and invalid CPU targets in the configuration.

## [5.0.0] — 2026-02-10

**The "Neural Sovereign" Update**
This release marks the fundamental transition of PMan from a heuristic script to a **Cognitive Autonomous Agent**. The system now possesses a "Mind" (Prediction), a "Conscience" (Authority Budget), and a "Hand" (Sandbox Executor). It no longer just applies tweaks; it negotiates with the OS.

### 🚀 Neural Autonomy & Intelligence
- **Shadow Execution Layer:** Implemented a simulation engine that predicts the outcome of an optimization *before* applying it.
- **Reality Sampler:** A feedback loop that measures the *actual* system response to an intervention. If the result doesn't match the prediction, the agent lowers its own confidence.
- **Confidence Tracker:** Statistical belief modeling. The AI now vets its own decisions based on historical accuracy (Fast-Start Momentum + Adaptive Variance).
- **Traffic Enforcer:** A "Reflex" architecture that bypasses the slow cognitive loop for instant, sub-millisecond boosts during sudden load spikes.
- **The System Detective:** An investigative module that resolves ambiguous system states (e.g., distinguishing between a hung process and a loading screen).
- **Universal Defender Cooperation (DCM):** A new diplomacy layer that detects active Security/AV scans and "shields" them instead of fighting them for resources.
- **External Verdict Interface:** Support for third-party authority modules to veto PMan actions.

### 🛡️ Authority, Safety & Governance
- **Authority Budget:** The AI now has a finite "spending limit" for interventions. It must ration its authority to prevent system thrashing.
- **Reversible Action Sandbox:** Optimizations are no longer permanent. They are applied as **Time-Bound Leases**. If the AI crashes or stops "thinking," the lease expires, and Windows defaults are restored automatically.
- **Provenance Ledger:** An immutable, cryptographic audit trail of every decision.
    - **Counterfactual Logging:** The ledger now records *why* an action was rejected (e.g., "Rejected due to Low Confidence" or "Budget Exhausted").
    - **Decision Attribution:** Precise logging of which module (Governor, Arbiter, or Reflex) authorized a change.
- **Outcome Guard:** A safety tripwire that terminates an optimization immediately if system latency worsens beyond the predicted margin.
- **PolicyGuard:** Immutable Authority Contract enforcement. Policies are now treated as hard constraints that the AI cannot override.

### 🖥️ PMan Neural Center (GUI Overhaul)
- **Control Center:** Replaced the old settings menu with a comprehensive "Neural Center" dashboard.
- **Dynamic Policy Tab:** Visual controls for Authority Budget, Confidence Thresholds, and Variance Safety Rails.
- **Presets:** Added one-click "Safe Mode" and "Gamer Mode" policy presets.
- **Visual Feedback:** Added highlight effects to active tabs and theme-aware icons for the tray context menu.
- **Double-Click Shortcut:** Double-clicking the tray icon now opens the Neural Center directly.

### ⚡ Deep System Optimization
- **SRAM Upgrade:** Added DPC/ISR Kernel Latency monitoring for detecting hardware-level stalls.
- **Wait Chain Traversal:** Implemented anti-deadlock detection logic in the Executor.
- **Working Set Hardening:** New memory optimization strategy that protects active process memory from being paged out during pressure.
- **Queue Depth Saturation:** The Governor now detects CPU Run Queue saturation to identify true thread contention.

### 🐛 Bug Fixes
- **Critical:** Replaced `GetTickCount` with `GetTickCount64` to resolve potential overflow crashes (C28159).
- **Persistence:** Fixed an issue where the Predictive Model (Brain) failed to save learned weights on exit.
- **Logic:** Resolved a conflict where Game Mode priority enforcement fought with PMan's internal booster.
- **Safety:** Added ETW congestion checks to prevent the monitoring subsystem from destabilizing the system.
- **Concurrency:** Fixed race conditions in the background process scanner and Explorer booster.
- **GUI:** Corrected log viewer scrolling behavior, signed/unsigned mismatches, and text truncation in tooltips.
- **Hardware:** Fixed topology detection issues on ARM64 devices.

### 🔧 Refactoring & Performance
- **Optimization:** Applied rigorous system optimization suite to the agent itself.
- **Stability:** Reduced EMA (Exponential Moving Average) alpha to 0.05 for more stable variance tracking.
- **Cleanup:** Integrated standalone "TuneUp" tools directly into the Control Panel.
- **Architecture:** Unified integer input controls and centralized background app throttling defaults.

---

## [Initial Public Baseline] — 2025-01-16

This release represents the **first formal documentation and feature baseline** for PMan.

### Added
- Complete system architecture and performance management suite
- ETW-based process and graphics event monitoring
- IOCP-driven asynchronous policy engine
- Multi-threaded background workers
- Session-scoped optimization with Crash-Resilient registry guard