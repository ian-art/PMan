# Security Model & Trust Boundaries

## Core Philosophy: The Licensed Operator

PMan v5 operates on a **"Licensed Operator"** security model. Unlike traditional tools that execute commands unconditionally, PMan acts as an autonomous agent that must possess a valid "License" (Authority Budget) and "Mandate" (Policy) to touch the Windows Kernel.

If the Agent violates its Policy, runs out of Budget, or fails to write to its Audit Log, its authority is actively revoked by the internal `OutcomeGuard`.

---

## 1. The Policy Contract (`policy.json`)

The `policy.json` file is the "Constitution" of the agent.
* **Hard Constraints:** It defines the maximum `AuthorityBudget` and `MinConfidence`. The C++ code cannot override these values at runtime.
* **Integrity Check:** The policy is hashed on load (SHA/CityHash). Every action recorded in the `ProvenanceLedger` includes this hash, providing a forensic link between the action taken and the policy active at that moment.
* **Failure Mode:** If `policy.json` is missing or malformed, the system fails closed (defaults to `BrainAction::Maintain` or safe hardcoded defaults).

## 2. External Verdict Interface (Enterprise Override)

PMan supports a file-based **External Verdict** protocol, allowing third-party security software or enterprise scripts to veto the agent.
* **Mechanism:** The agent checks for a `verdict.json` file in its root directory before every execution cycle.
* **Protocol:** The file must contain a valid directive (`ALLOW`, `DENY`, or `CONSTRAIN`) and a future Unix timestamp (`expires_at_unix`).
* **Fail-Closed:** If the verdict file exists but contains `DENY` or is expired, the Agent is immediately forbidden from acting.
* **Use Case:** An Admin can drop a `DENY` verdict file to instantly halt all PMan instances during a software update without needing to kill the process.

## 3. Provenance & Accountability

**Problem:** Autonomous systems are often "Black Boxes."
**Solution:** **Structured Audit Log**.
* **Forensic Trail:** Every decision is logged to `provenance.log` in a structured JSON format. This includes the input telemetry, the decision made, and the specific cost/benefit analysis.
* **Counterfactuals:** The log records *why* an action was taken, and crucially, *why alternatives were rejected* (e.g., "Rejected Boost due to Budget Exhaustion").
* **Write Assurance:** If the Log file is locked, read-only, or the disk is full, the `OutcomeGuard` disables the Executor. The agent is hard-coded to stop acting if it cannot create a record of its actions.

## 4. Sandbox Isolation (The Dead Man's Switch)

PMan never permanently modifies system state.
* **Leased Authority:** Optimizations (e.g., Priority Boosts) are applied as "Leases" (default 5000ms).
* **Automatic Reversion:** If the Agent crashes, hangs, or is terminated by Task Manager, the Leases expire. The OS naturally reverts the process handles, or the `RegistryGuard` restores global settings.
* **Benefit:** A compromised or buggy agent cannot leave the system in a permanently unstable state.

## 5. Privilege & Data

### Administrative Rights
PMan requires Administrator privileges to:
* Manage Process Priorities (`OpenProcess` with `PROCESS_SET_INFORMATION`).
* Manage Services (Suspension/Resumption).
* Read ETW Kernel Traces (Context Switches).

### Data Privacy
* **Local Only:** All learning data (`brain.bin`), logs (`provenance.log`), and profiles are stored locally in `%ProgramData%\PriorityMgr`.
* **No Telemetry:** PMan v5 contains **Zero Telemetry**. It does not report decisions, hardware specs, or user habits to any server.
* **Network:** The only network activity is:
    1.  ICMP Pings to `1.1.1.1` / `8.8.8.8` (Latency/Jitter checks).
    2.  Localhost/Loopback traffic for IPC (if applicable).

## 6. Attack Surface Reduction

* **No Kernel Driver:** PMan runs entirely in User Mode. It cannot cause a Blue Screen of Death (BSOD) directly.
* **Input Sanitization:** The `Investigator` module sanitizes inputs (Process Names) before they enter the Decision Engine.
* **Budgeting as Defense:** Even if the internal logic is tricked into "Spamming" optimizations, the `AuthorityBudget` will deplete instantly, locking the agent out of the system.