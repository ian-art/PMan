<div align="center">

# ⚡ Priority Manager (PMan) v6

### The Autonomous Adaptive Control System for Windows

*"Tune once. Let the system adapt."*

</div>

---

**Priority Manager (PMan)** is a **closed-loop autonomous agent** that acts as a **Governor** for your Operating System. Unlike static priority tools, PMan observes system telemetry, predicts the consequences of optimization using statistical models, executes changes in a sandbox, and measures the actual reality of those changes to learn over time.

---

## 🧠 The Core Logic: Cognitive Control Loop

PMan v5 moves beyond static "If/Then" heuristics to a **Feedback Control Loop**:

1. **Observation**: Captures CPU variance, thermal throttling, and input latency via the **SRAM** engine.
2. **Prediction**: The **Predictive Model** calculates the expected cost of intervention using historical variance data.
3. **Arbitration**: The **Decision Arbiter** weighs the proposal against a finite **Authority Budget**.
4. **Execution**: Changes are applied via the **Sandbox Executor** using time-bound "leases" (e.g., 5 seconds).
5. **Reality Sampling**: The system measures if the tweak actually reduced lag. If not, the **Confidence Tracker** penalizes the model, reducing the likelihood of repeating the mistake.

---

## 🛡️ Safety Architecture

PMan is built on a "Do No Harm" architecture designed to fail closed.

### 1. The Decision Engine

- **Performance Governor**: Analyzes dominant pressure (CPU vs. Disk vs. Latency) to propose strategies.
- **Consequence Evaluator**: Estimates the "cost" of action (e.g., "Throttling background apps may increase I/O wait").
- **Authority Budget**: The agent has a limited "allowance" of interventions per minute. If budget is exhausted, it is locked out until it regenerates.
- **Adaptive Confidence**: Uses a **Contextual Bandit** approach (Mean Error & Variance tracking) to adjust aggression. High prediction error leads to "hesitation" in future actions.

### 2. Safety & Provenance

- **Provenance Ledger**: A structured JSON audit log that records every decision, the active policy hash, and the reasons for rejecting alternatives.
- **Outcome Guard**: A reactive layer that triggers an immediate **Rollback** if the observed state diverges dangerously from the prediction.
- **SRAM (System Responsiveness Awareness Module)**: A detached sidecar thread that actively probes UI latency (`SendMessageTimeout`) to detect micro-stutters standard metrics miss.
- **Registry Guard**: A crash-resilient watchdog process that restores default Windows settings if the main agent crashes or is terminated.

### 3. Hardware Integration

- **Hybrid Topology Awareness**: Distinguishes between P-Cores and E-Cores (Intel/AMD) to pin background threads away from critical tasks.
- **Input Guardian**: Monitors raw HID interrupts to bias the foreground window the millisecond user activity is detected.
- **Network Intelligence**: Uses `qWave` QoS and standard ping probes to detect bufferbloat and deprioritize background transfer traffic.

---

### 4. Anti-Cheat Compliance

PMan is engineered to be **100% compliant** with modern anti-cheat systems (BattlEye, EAC, Vanguard). It operates strictly as an external system scheduler.

* ✅ **No Hooks:** System-wide input hooks have been removed.
* ✅ **No Injection:** Does not touch game memory or code.
* ✅ **Standard APIs:** Uses only documented Windows OS calls.

[👉 **Read the full Anti-Cheat Safety Audit**](docs/ANTICHEAT.md)

---

## 🎮 Features

| Feature | Description |
|---------|-------------|
| **Policy Control** | Configure the agent's behavior via `policy.json`. Define the **Authority Budget** and **Confidence Thresholds**. |
| **Live Audit** | View the decision chain in real-time. See the Arbiter reject actions due to "Low Confidence" or "Budget Exhausted." |
| **Sandbox Leasing** | Optimizations are temporary "leases." If the agent crashes, the lease expires, and Windows defaults are automatically restored. |
| **Hang Recovery** | The `ResponsivenessManager` detects hung applications (Window Ghosting) and applies soft thread boosts to attempt recovery. |
| **External Verdict** | Supports an enterprise override via `verdict.json` to strictly `ALLOW` or `DENY` actions based on external requirements. |

---

## ⚙️ Configuration (Titanium Architecture)

**⚠️ Note:** PMan v6 no longer supports manual editing of configuration files.
Attempting to edit `config.dat` manually will trigger a Tamper Detection event and force a Factory Reset.

Configuration is now managed exclusively via the **Neural Center GUI**, which communicates with the System Service via a secure, encrypted IPC channel.

**Security Features:**
* **RBAC Enforcement:** Only Administrators can write changes to the system policy.
* **DPAPI Encryption:** Configuration is encrypted with `CRYPTPROTECT_SYSTEM`, ensuring only the localized System Service can read it.
* **Input Validation:** The Service acts as a "Gatekeeper," rejecting invalid values before they touch the disk.

---

## 🔧 Technical Specs

| Category | Details |
|----------|---------|
| **Language** | C++20 (Concepts, Coroutines, Atomics) |
| **Concurrency** | Lock-free telemetry, IOCP for file watching, and Thread Pool. |
| **Persistence** | `brain.bin` (Statistical weights), `config.dat` (Encrypted Settings). |
| **Dependencies** | Native Win32 API only. No external runtime required. |

---

## ⚠️ Requirements

- **OS**: Windows 10 (2004+) or Windows 11 (Required for Hybrid Architecture APIs).
- **Privileges**: Administrator (Required for `NtSetInformationProcess` and Service Control).

---

## 🛠️ Building from Source

To ensure a clean, high-performance binary that is free of false positives, use the following MSVC build command. This configuration explicitly defines the application's security context and subsystem, preventing heuristic misidentifications.

**Prerequisites:** Visual Studio 2022 (MSVC)

> **⚠️ Crash Reporter Compliance**
> The flags `/Zi`, `/DEBUG:FULL`, and `/INCREMENTAL:NO` are **strictly required**. They generate the PDB symbols necessary for the internal Crash Reporter to accurately map stack traces in minidumps. Removing these flags will render the "Flight Recorder" and "Watchdog" systems unable to analyze crashes.

pman:

```cmd
cl /std:c++latest /EHsc /O2 /GL /W4 /MP Zi^
   /I include src\*.cpp pman.res /Fe:pman_x64.exe ^
   /link /OPT:REF /OPT:ICF /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup ^
   /INCREMENTAL:NO /MANIFEST:EMBED /MANIFESTUAC:level='requireAdministrator' ^
   Advapi32.lib User32.lib Shell32.lib Ole32.lib Tdh.lib Wtsapi32.lib ^
   /DEBUG:FULL
```

pmanwatchdog:

```cmd
cl /std:c++latest /nologo /Od /Zi /EHsc /D UNICODE /D _UNICODE ^
 main.cpp pmanwatchdog.res /Fe:pmanwatchdog.exe ^
 /link /MANIFEST:EMBED /MANIFESTUAC:level='requireAdministrator' ^
 /OPT:REF /OPT:ICF /INCREMENTAL:NO ^
 Dbghelp.lib Kernel32.lib User32.lib ^
 /DEBUG:FULL
```

---

## 🛡️ Antivirus Note

If you download a pre-compiled binary, some antivirus solutions (like SecureAge) may flag it due to the embedded icon or C++20 standard library patterns ("Wacatac.B!ml").

**Solution:**
I strongly recommend **building the software yourself** using the command provided in the [Building from Source](#%EF%B8%8F-building-from-source) section above. The official build configuration has been verified to produce a clean binary.

> **⚠️ OFFICIAL SOURCE WARNING**
>
> This GitHub repository is the **only** trusted source for PMan. Do not download the program from third-party sites. For maximum security, build the software locally using the official instructions.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

**What this means:** You can freely use, modify, and distribute this software, but any derivative work must also be released under GPL-3.0 with its source code available.

See the `LICENSE` file for the full license text.

---

## Third-Party Components

This project includes the following third-party software:

**Dear ImGui**
* Copyright (c) 2014–2026 Omar Cornut
* License: MIT
* https://github.com/ocornut/imgui

**JSON for Modern C++**
* Copyright (c) 2013-2026 Niels Lohmann
* License: MIT
* https://github.com/nlohmann/json

---

<div align="center">

**Neural Origin:** Ian Anthony R. Tancinco  
**Synthetic Cortex:** Gemini, GPT, Claude, Kimi, and others.

*"The system is not sovereign. It is a licensed operator."*

</div>