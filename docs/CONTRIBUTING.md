# Contributing to PMan v5

## Core Philosophy: The System is Sovereign

PMan v5 is not a "tweaking tool"; it is an **Autonomous Governor**. When you contribute code, you are not writing a script to change settings—you are building a cognitive subsystem.

**The Golden Rule:**
> **No component shall modify the System State directly except the `SandboxExecutor`.**

---

## 🏗️ Architecture Compliance

### 1. The Sandbox Barrier
You are **strictly forbidden** from calling `SetPriorityClass`, `SetProcessAffinityMask`, or `NtSetInformationProcess` directly in any logic module (`governor.cpp`, `policy.cpp`, etc.).
* **Wrong:** calling `SetPriorityClass` inside `Governor::Decide`.
* **Right:** The Governor proposes a `BrainAction`, and the `SandboxExecutor` applies it *if and only if* the budget allows.

### 2. Mandatory Reversibility (The Lease Protocol)
Every new optimization must be designed as a **Time-Bound Lease**.
* **Requirement:** If you add a new `BrainAction` (e.g., `Optimize_IO`), you must implement a corresponding `Rollback()` method in the Sandbox.
* **Crash Safety:** If the agent stops "thinking" (renewing the lease), your feature must automatically expire and return Windows to its default state.

### 3. Prediction Required
You cannot add an action without defining its Cost.
* **Shadow Execution:** Update `ShadowExecutor::Simulate()` to predict what your action *should* do (e.g., "This will lower CPU usage by 5%").
* **Cost Vector:** Update `ConsequenceEvaluator` to assign a cost to your action. (e.g., "Does this risk audio starvation?").

### 4. Provenance & Audit
"If it isn't in the Ledger, it didn't happen."
* Any new decision pathway must be logged to `ProvenanceLedger`.
* You must record **Counterfactuals**: If your logic rejects an action, you must log *why* (e.g., `RejectionReason::BudgetInsufficient`).

---

## 💻 Coding Guidelines

### 1. Resource Management (RAII)
**Strictly Enforced.** Memory leaks in a long-running agent are fatal.
* **Handles:** Use `UniqueHandle` for `HANDLE`.
* **Registry:** Use `UniqueRegKey` for `HKEY`.
* **Allocations:** Use `std::unique_ptr` or `std::shared_ptr`. Raw `delete` is forbidden.

### 2. No Loose Globals
* **State:** Use the `PManContext` singleton for application state.
* **Concurrency:** Use `std::atomic` for variables shared between the UI thread and worker threads (e.g., `LagStatus` in SRAM).

### 3. Windows API Abstraction
* **NT APIs:** Do not call `GetProcAddress`. Use `NtWrapper` for all `Nt*` functions.
* **Capabilities:** Check `OSCapabilities` (`g_caps`) before using features like EcoQoS or Hybrid Core detection.

### 4. Safety First
* **Registry Caching:** Always use `RegWriteDwordCached` to prevent registry hammering
* **Verification:** Every optimization function must verify the `(PID, CreationTime)` tuple before applying changes to prevent PID reuse attacks.

---

## 🧪 Testing Your Contribution

1.  **The "Crash Test":** Kill `pman.exe` via Task Manager while your feature is active.
    * *Pass:* The system reverts to default behavior within 5 seconds (via `RegistryGuard`).
    * *Fail:* The optimization sticks permanently.
2.  **The "Audit Test":** Check the Live Log.
    * *Pass:* You see a `[PROVENANCE]` entry explaining why your action was taken.
    * *Fail:* The action happens silently.