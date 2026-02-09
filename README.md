<div align="center">

# ⚡ Priority Manager (PMan) v5

### The Autonomous Neural Orchestrator for Windows

*"Tune once. Let the system adapt."*

</div>

---

**Priority Manager (PMan)** is not just a priority toggler. It is a **closed-loop autonomous agent** that acts as a **Governor** for your Operating System. It observes system telemetry, predicts the consequences of optimization, executes changes in a sandbox, and measures the actual reality of those changes to learn over time.

---

## 🧠 The Shift: From Heuristics to Agency

Traditional optimizers use **static rules** ("If Game, Then High Priority"). **PMan v5** uses a **Cognitive Control Loop**:

1. **Observation**: Captures CPU variance, thermal throttling, and input latency (`SystemSignalSnapshot`).
2. **Prediction**: The Shadow Executor simulates "what if" scenarios before touching the system.
3. **Arbitration**: The Decision Arbiter weighs the cost of intervention against the Authority Budget.
4. **Execution**: Changes are applied via the Sandbox Executor with an automatic rollback lease.
5. **Reality Sampling**: The system measures if the tweak actually reduced lag. If not, it reverts and lowers its own confidence.

---

## 🛡️ Core Systems (The Neural Stack)

PMan v5 is built on an advanced **safety-first architecture** designed to prevent "optimization" from becoming the bottleneck.

### 1. The Decision Engine

- **Performance Governor**: Analyzes raw telemetry to propose interventions.
- **Consequence Evaluator**: Calculates the "cost" of an action (e.g., will boosting a game starve audio?).
- **Authority Budget**: The AI has a limited "allowance" of interventions. If it spends too much authority without results, it is locked out until it "cools down."
- **Confidence Tracker**: Dynamically adjusts aggression based on prediction error. If the AI makes a mistake, it hesitates next time.

### 2. Safety & Provenance

- **Provenance Ledger**: Every decision—even the decision to do nothing—is cryptographically hashed and logged. You get a receipt for why the AI acted.
- **Outcome Guard**: A reactive layer that triggers an immediate rollback if the observed state diverges dangerously from the prediction.
- **SRAM (System Responsiveness Awareness Module)**: Monitors the "feeling" of the OS. If the UI lags, PMan yields immediately.
- **Registry Watchdog**: A crash-resilient guard process that restores default Windows settings if PMan acts erratically or crashes.

### 3. Hardware Integration

- **Hybrid Topology Awareness**: Distinguishes between P-Cores and E-Cores (Intel/AMD) to pin background threads away from your game.
- **Input Guardian**: Monitors HID devices to boost the foreground window the millisecond you move your mouse.

---

## 🎮 Features

| Feature | Description |
|---------|-------------|
| **Neural Center** | Configure the "Brain" parameters via `policy.json`. Define how much authority the AI has. |
| **Live Audit** | View the Provenance Ledger in real-time. See the AI reject actions due to "Low Confidence" or "Budget Exhausted." |
| **Sandbox Execution** | Optimizations are "leased." If the system doesn't renew the lease (because performance dropped), Windows defaults are restored instantly. |
| **Responsiveness Recovery** | Automatically detects hung applications (Window Ghosting) and applies soft thread boosts to recover them without killing. |
| **Tray Animation** | Visual feedback on the system state (Snappy, Pressure, Lagging, Critical) via the tray icon. |

---

## ⚙️ Configuration

PMan v5 is controlled via **Policies** (`policy.json`).
```json
{
  "limits": {
    "maxAuthorityBudget": 1000,
    "allowedActions": ["Maintain", "BoostForeground", "IsolateBackground"],
    "minConfidence": {
      "cpuVariance": 0.85
    }
  }
}
```

- **Authority Budget**: Defines how many "credits" the AI can spend on interventions per minute.
- **Min Confidence**: The AI will refuse to act if its prediction confidence is below this threshold.

---

## 🔧 Technical Specs

| Category | Details |
|----------|---------|
| **Language** | C++20 (utilizing Concepts, Coroutines, and Atomics) |
| **Concurrency** | Lock-free circular buffers, IOCP (I/O Completion Ports), and Thread Pool. |
| **Persistence** | `brain.bin` (Learned weights), `provenance.log` (Audit trail). |
| **Dependencies** | Native Win32 API only. No external runtime required. |

---

## ⚠️ Requirements

- **OS**: Windows 10 (2004+) or Windows 11 (Required for Hybrid Architecture APIs).
- **Privileges**: Administrator (Required for `NtSetInformationProcess` and Service Control).

---

## 📄 License

**GNU General Public License v3.0 (GPL-3.0)**.

Source Code: [Available on GitHub]

---

<div align="center">

**Architect:** Ian Anthony R. Tancinco  
**Engineers:** Gemini, GPT, Claude, Kimi, and others.

*"The system is not sovereign. It is a licensed operator."*

</div>