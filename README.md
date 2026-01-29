<div align="center">

# ⚡ Priority Manager (PMan)

### A zero-latency Windows performance daemon for games and productivity

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B20-orange)
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

## 🚀 Key Features (Optimized for Legacy & Standard Architectures)

### 🧠 CPU Topology & Thread Management

**Smart SMT / Hyper‑Threading Control**

* Dynamically manages logical cores to reduce jitter and cache contention
* Re‑enables SMT for multitasking and browser workloads to maximize throughput on standard multi-core CPUs.

**Audio Isolation (The Crackle Fixer)**

* Automatically detects audio engines (`audiodg.exe`)
* **Pins audio threads to the last physical core** to prevent buffer underruns and "crackling" during heavy CPU loads
* Ensures `HIGH_PRIORITY_CLASS` for audio processing

**Legacy Game Support**

* Dedicated detection for older titles (DirectX 9/10) that do not trigger modern presentation events
* Ensures classic games receive the same high-performance scheduling as modern titles

---

### ⚡ Deep System Optimization

**Win32 Priority Separation**

* Dynamically adjusts the CSRSS scheduler quantum to favor foreground windows:

| Mode            | Value  | Behavior                                             |
| --------------- | ------ | ---------------------------------------------------- |
| 🎮 Game Mode    | `0x28` | Short, variable quantums for smooth frame pacing     |
| 🌐 Browser Mode | `0x26` | Optimized for responsiveness and background services |

**Timer Resolution & Coalescing**

* Forces **0.5 ms (5000 units)** global timer resolution during gaming for maximum precision
* Disables timer coalescing to reduce input latency
* Re‑enables coalescing during browsing for power efficiency

**I/O & GPU Priority**

* Elevates **Game I/O priority → High**
* Lowers background browser I/O priority to prevent stutters during downloads

---

### 📡 Network Intelligence & Latency Control

**Adaptive Network Throttling**

* Monitors your **Qualcomm Atheros Wi-Fi** connection stability in real-time
* Automatically throttles background processes (Windows Update, BITS) when latency spikes are detected
* Prevents background bandwidth hogs from causing lag spikes during online gaming

**Auto-Repair Mechanism**

* Detects connection drops (>5s) and attempts soft repairs (DNS Flush, IP Renew) automatically

---

### 💾 Memory & Resource Management

**Context-Aware Memory Optimization**

* Monitors system memory pressure (Hard Page Faults)
* **Gaming:** Expands working set limits to prevent paging to disk
* **Browsers:** Applies "EcoQoS" and trims memory only when strictly necessary (e.g., system RAM > 85% full)

**Disk Thrashing Protection**

* Temporarily pauses high-I/O services during gaming to prevent disk stutter:
  * `wsearch` (Windows Search)
  * `sysmain` (Superfetch)
  * `wuauserv` (Windows Update)
* Preserves disk I/O bandwidth for the active game

---

### 🛡️ Stability & Safety

**Crash-Resilient Architecture**

* **Registry Watchdog:** A dedicated guard process ensures system settings are restored even if the main app is forced to close
* **Service Recovery:** Guaranteed auto-resume of paused services upon exit

**System Responsiveness Awareness (SRAM)**

* Monitors UI latency and DWM composition drops in real-time
* Automatically yields CPU if the system detects critical lag, preventing the "optimizer" from becoming the bottleneck

---

## ⚙️ Configuration

**Hot‑Reloadable Configuration**

* Edit `config.ini` **in real time**
* Uses **I/O Completion Ports (IOCP)** to watch file changes
* No restart required

**System Tray Controls**

* **Passive Mode:** Disable CPU throttling while keeping other optimizations active
* **Keep Awake:** Prevent system sleep/screen-off during critical tasks
* **Live Log:** View real-time performance decisions via the tray menu

---

## 🔧 Technical Details

| Category     | Details                               |
| ------------ | ------------------------------------- |
| Language     | C++20                                 |
| Architecture | Event‑Driven (ETW + IOCP + WinEvents) |
| Dependencies | Native Win32 API only                 |
| Libraries    | `ntdll.lib`, `tdh.lib`, `pdh.lib`     |

**Key APIs Used**

* `NtSetInformationProcess` *(undocumented process priorities)*
* `NtSetTimerResolution` *(global timer precision)*
* `SetProcessWorkingSetSizeEx` *(RAM control)*
* `GetExtendedTcpTable` *(Network monitoring)*

---

## 📥 Installation & Usage

1. **Download**
   * Grab the latest release or build from source

2. **Run**
   ```
   pman.exe
   ```

3. **First Launch**
   * Installs a scheduled task
   * Runs automatically at logon with Highest Privileges

4. **Configuration File**
   ```
   C:\ProgramData\PriorityMgr\config.ini
   ```
   * Add executables under `[games]`
   * Add browsers under `[browsers]`

5. **Uninstall**
   ```
   pman.exe --uninstall
   ```

---

## ⚠️ Requirements

* **OS:** Windows 10 (1809+) or Windows 11
* **Privileges:** Administrator (kernel, registry, and service control)
* **Hardware:**
  * Optimized for Standard Multi-Core CPUs (Intel Core 1st Gen+, AMD Ryzen, etc.)
  * Memory: 4GB+ RAM Recommended
  * Network: Wi-Fi or Ethernet adapter for latency management

---

## 🗂️ Source Layout

| File          | Responsibility                                                                 |
| ------------- | ------------------------------------------------------------------------------ |
| `main.cpp`    | Entry point, handles --uninstall, global mutex, scheduled task, subsystem init |
| `events.cpp`  | Core engine: ETW kernel events + IOCP config watcher                           |
| `tweaks.cpp`  | Low‑level tuning: priorities, affinities, RAM, NT API calls                    |
| `policy.cpp`  | Decision logic: hysteresis, cooldowns, session locking                         |
| `sysinfo.cpp` | Hardware detection: CPUID & System capabilities                                |
| `services.cpp`| Windows Service Control Manager (wuauserv, BITS, SysMain)                      |
| `config.cpp`  | INI parsing and Unicode handling                                               |

---

## License

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

---

## VirusTotal

`e573a3ec40b681f7d9ef89b75d6166a43a931c0454a3b2952ab0cd8794641876`

---

<details>
<summary><small>Notes</small></summary>

<small>

All these are AI-generated codes and AI-generated fixes, but everything is my core idea.

Tested and running on my Sony VPCCW21FX laptop without issues.

**Architect:** Ian Anthony R. Tancincο  
**Engineers:** Gemini, GPT, Claude, Kimi, and others.

Further testing on other devices is required.

</small>

</details>

---

<div align="center">

**Priority Manager — Tune once. Let the system adapt.**

</div>
