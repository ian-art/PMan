<div align="center">

# ⚡ Priority Manager (PMan)

### A zero-latency Windows performance daemon for games and productivity

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B17-orange)
![Architecture](https://img.shields.io/badge/Architecture-Event--Driven-success)
![Privileges](https://img.shields.io/badge/Privileges-Administrator-red)

</div>

---

## 🧩 Overview

**Priority Manager (PMan)** is a high‑performance, background Windows optimization daemon written in **modern C++**. It automatically detects active applications and dynamically tunes the **Windows scheduler, memory subsystem, and CPU topology** to maximize:

* 🎮 **Frame pacing & latency** during gaming
* 🧑‍💻 **Responsiveness & efficiency** during browsing and multitasking

Unlike traditional priority tools that *poll* processes (wasting CPU cycles and adding latency), **PMan is fully event‑driven**. It uses **Event Tracing for Windows (ETW)** to detect process start/stop events with **near‑zero latency** and **negligible overhead**.

---

## 🚀 Key Features

### 🧠 Intelligent CPU Topology Management

**Intel Hybrid Architecture (12th–14th Gen)**

* Automatically pins games to **P‑Cores (Performance cores)**
* Pushes browsers and background tasks to **E‑Cores (Efficiency cores)**
* Uses `SetProcessDefaultCpuSets` for clean, scheduler‑aware affinity control

**AMD Ryzen X3D (3D V‑Cache Optimization)**

* Detects CCD topology at runtime
* Pins games to the **V‑Cache CCD (CCD0)**
* Restores full multi-CCD access (V-Cache + Frequency) for browsers, allowing the OS to utilize all cores for maximum multitasking throughput.

**SMT / Hyper‑Threading Control**

* Dynamically disables logical cores for games to reduce jitter and cache contention
* Re‑enables SMT for multitasking and browser workloads

---

### ⚡ Deep System Optimization

**Win32 Priority Separation**

* Dynamically adjusts the CSRSS scheduler quantum

| Mode            | Value  | Behavior                                             |
| --------------- | ------ | ---------------------------------------------------- |
| 🎮 Game Mode    | `0x28` | Short, variable quantums for smooth frame pacing     |
| 🌐 Browser Mode | `0x26` | Optimized for responsiveness and background services |

**Timer Resolution & Coalescing**

* Forces **0.5 ms (5000 units)** global timer resolution during gaming
* Disables timer coalescing for real‑time precision
* Re‑enables coalescing during browsing for power efficiency

**I/O & GPU Priority**

* Elevates **Game I/O priority → High**
* Elevates **GPU scheduling priority → High** (Hardware Scheduling required)
* Lowers browser I/O priority to prevent stutters during downloads or tab loading

---

### 💾 Memory & Resource Management

**Working Set Enforcement**

* 🎮 Games: expands working set limits to prevent paging
* 🌐 Browsers: aggressively trims unused pages when a game starts

**Intelligent Standby List Purge**

* Monitors memory pressure in real time
* Purges cached RAM **only when necessary** (never blindly)

**Kernel Paging Enforcement**

* Temporarily enables DisablePagingExecutive during gaming
* Prevents the Windows Kernel from paging core drivers and system code to disk, eliminating micro-stutters caused by disk I/O on hot paths.

---

### 🛡️ Stability & Automation

**Zero‑Latency Detection**

* Kernel ETW session (`KernelProcessGuid`) for instant process detection
* Fallback to `SetWinEventHook` for foreground window changes

**Anti‑Interference Watchdog**

* Monitors registry keys for interference from other “optimizer” tools
* Automatically re‑asserts preferred policies if overwritten

**Service Throttling**

* Temporarily pauses:

  * `wuauserv` (Windows Update)
  * `BITS` (Background Intelligent Transfer Service)
* Preserves bandwidth and CPU during gameplay

**Graceful Shutdown**

* Restores all registry keys, services, and timer resolutions to Windows defaults

---

## ⚙️ Configuration

**Hot‑Reloadable Configuration**

* Edit `config.ini` **in real time**
* Uses **I/O Completion Ports (IOCP)** to watch file changes
* No restart required

**Session Locking**

* Prevents mode flapping
* Once a game is running, the system remains in **Game Mode** even during Alt‑Tab

---

## 🔧 Technical Details

| Category     | Details                               |
| ------------ | ------------------------------------- |
| Language     | C++20                                 |
| Architecture | Event‑Driven (ETW + IOCP + WinEvents) |
| Dependencies | Native Win32 API only                 |
| Libraries    | `ntdll.lib`, `tdh.lib`                |

**Key APIs Used**

* `NtSetInformationProcess` *(undocumented process priorities)*
* `NtSetTimerResolution` *(global timer precision)*
* `SetProcessWorkingSetSizeEx` *(RAM control)*
* `PowerSettingNotification` *(power plan awareness)*

---

## 📥 Installation & Usage

1. **Download**

   * Grab the latest release or build from source

2. **Run**

   ```text
   pman.exe
   ```

3. **First Launch**

   * Installs a scheduled task
   * Runs automatically at logon with **Highest Privileges**

4. **Configuration File**

   ```text
   C:\ProgramData\PriorityMgr\config.ini
   ```

   * Add executables under `[games]`
   * Add browsers under `[browsers]`

5. **Uninstall**

   ```text
   pman.exe --uninstall
   ```

---

## ⚠️ Requirements

* **OS**: Windows 10 (1809+) or Windows 11
* **Privileges**: Administrator (kernel, registry, and service control)
* **Hardware**:

  * Optimized for Intel Hybrid CPUs (12th Gen+)
  * Optimized for AMD Ryzen X3D
  * Fully functional on all modern multi‑core CPUs

---

## 🗂️ Source Layout

| File           | Responsibility                                                                   |
| -------------- | -------------------------------------------------------------------------------- |
| `main.cpp`     | Entry point, handles `--uninstall`, global mutex, scheduled task, subsystem init |
| `events.cpp`   | Core engine: ETW kernel events + IOCP config watcher                             |
| `tweaks.cpp`   | Low‑level tuning: priorities, affinities, RAM, NT API calls                      |
| `policy.cpp`   | Decision logic: hysteresis, cooldowns, session locking                           |
| `sysinfo.cpp`  | Hardware detection: CPUID hybrid flags & AMD cache topology                      |
| `services.cpp` | Windows Service Control Manager (wuauserv, BITS)                                 |
| `config.cpp`   | INI parsing and Unicode handling                                                 |

---

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

**What this means**: You can freely use, modify, and distribute this software, but any derivative work must also be released under GPL-3.0 with its source code available.

See the [LICENSE](LICENSE) file for the full license text.

## Third-Party Components

This project includes the following third-party software:

- **Dear ImGui**
  - Copyright (c) 2014–2026 Omar Cornut
  - License: MIT
  - https://github.com/ocornut/imgui

**VirusTotal**
`e573a3ec40b681f7d9ef89b75d6166a43a931c0454a3b2952ab0cd8794641876`

<details>
<summary><small>Notes</small></summary>

<small>
All these are AI-generated codes and AI-generated fixes, but everything is my core idea.<br>
Tested and running on my Sony VPCCW21FX laptop without issues.<br><br>

Architect: `Ian Anthony R. Tancinco`<br>
Engineers: `Gemini, GPT, Claude, Kimi, and others.`<br><br>

`Further testing on other devices is required.`
</small>

</details>

<div align="center">

**Priority Manager** — *Tune once. Let the system adapt.*

</div>
