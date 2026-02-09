# Configuration & Tuning Guide

PMan v5 is an **Autonomous Agent**. Unlike traditional tools where you toggle "Game Mode" on or off, PMan operates on a dynamic **Policy**. You define the *rules of engagement*, and the agent decides *when* to act.

This configuration is managed via the **Neural Center** (Tray Icon → Double Click) or by editing `policy.json`.

---

## 🧠 The Neural Policy (`policy.json`)

The policy file controls the "personality" of the AI. It determines how aggressive the agent is and how much risk it is allowed to take.

### 1. Authority Budget (`maxAuthorityBudget`)

- **Definition:** The maximum "political capital" the agent can spend in a rolling window (typically 60 seconds).
- **Cost Table:**
  - `Maintain`: 0 (Free)
  - `Boost_Process`: 1 (Cheap)
  - `Throttle_Mild`: 5
  - `Optimize_Memory`: 10
  - `Throttle_Aggressive`: 15
  - `Release_Pressure` / `Shield_Foreground`: 20
  - `Suspend_Services`: 30 (Expensive)

### 2. Variance Tolerance (`minConfidence`)

- **Definition:** The allowed amount of system "Jitter" (CPU/Latency Variance) before the agent considers the system *unstable*.
- **Logic:**
  - **Low Value (0.01):** "Paranoid." The agent reacts to the slightest micro-stutter.
  - **High Value (4.0+):** "Tolerant." The agent ignores background noise and only fixes major lags.

---

## 🎮 Official Presets

These match the buttons found in the **Neural Center** GUI.

### Safest (Default)

Strict safety rails. Designed for office work or stability-critical environments.
```json
{
  "maxAuthorityBudget": 150,
  "minConfidence": {
    "cpuVariance": 0.01,
    "latencyVariance": 0.02
  },
  "allowedActions": [
    "Maintain", 
    "Boost_Process", 
    "Throttle_Mild", 
    "Optimize_Memory"
  ]
}
```

### Balanced

The recommended standard. Allows aggressive throttling of heavy background apps but forbids service suspension.
```json
{
  "maxAuthorityBudget": 300,
  "minConfidence": {
    "cpuVariance": 0.50,
    "latencyVariance": 1.00
  },
  "allowedActions": [
    "Maintain", 
    "Boost_Process", 
    "Throttle_Mild", 
    "Throttle_Aggressive", 
    "Optimize_Memory"
  ]
}
```

### Gamer

High authority. Allows the agent to suspend Windows Update services (`Suspend_Services`) and use emergency I/O boosting (`Release_Pressure`).
```json
{
  "maxAuthorityBudget": 1000,
  "minConfidence": {
    "cpuVariance": 4.0,
    "latencyVariance": 8.0
  },
  "allowedActions": [
    "Maintain", 
    "Boost_Process", 
    "Throttle_Mild", 
    "Throttle_Aggressive", 
    "Optimize_Memory",
    "Suspend_Services",
    "Release_Pressure",
    "Shield_Foreground"
  ]
}
```

### Insomnia / Tetris (Extreme)

**Warning:** These presets allow extreme variance (up to 50.0). This effectively disables the "Stability Governor," forcing the AI to intervene constantly, even if the system is chaotic. Use only for benchmarking.
```json
{
  "maxAuthorityBudget": 5000,
  "minConfidence": {
    "cpuVariance": 10.0,
    "latencyVariance": 20.0
  }
}
```