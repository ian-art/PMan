# Security Model & Trust Boundaries

## Core Philosophy: The Licensed Operator

PMan v5 operates on a **"Licensed Operator"** security model. Unlike traditional tools that execute commands unconditionally, PMan acts as an autonomous agent that must possess a valid "License" (Authority Budget) and "Mandate" (Policy) to touch the Windows Kernel.

If the Agent violates its Policy, runs out of Budget, or fails to record its actions in the Ledger, its authority is physically revoked by the internal `OutcomeGuard`.

---

## 1. The Policy Contract (`policy.json`)

The `policy.json` file is the immutable "Constitution" of the agent.
* **Hard Constraints:** It defines the maximum `AuthorityBudget` and `MinConfidence`. The C++ code cannot override these values at runtime.
* **Tamper Evidence:** The policy is hashed on load. Every action in the `ProvenanceLedger` includes this hash, proving which policy was active when the decision was made.
* **Failure Mode:** If `policy.json` is missing or malformed, the system fails closed (defaults to `BrainAction::Maintain` or safe defaults).

## 2. External Verdict Interface (Jurisdictional Boundary)

PMan supports an **External Verdict** protocol, allowing third-party security software or enterprise policies to veto the agent.
* **Mechanism:** The agent checks for signed/authorized verdict signals (implementation dependent) before every execution.
* **Fail-Closed:** If the verdict module is active but returns an error or "Deny", the Agent is immediately forbidden from acting.
* **Use Case:** An Enterprise Admin can push a "Halt" verdict to all PMan instances during a critical software update without killing the process.

## 3. Provenance & Accountability

**Problem:** Autonomous systems are often "Black Boxes."
**Solution:** **Cryptographic Provenance Ledger**.
* **Non-Repudiation:** Every decision is logged with a timestamp, policy hash, and input vector.
* **Counterfactuals:** The ledger records *why* an action was taken, and more importantly, *why alternatives were rejected*.
* **Integrity Check:** If the Ledger file is locked or unwritable, the `OutcomeGuard` disables the Executor. The agent cannot act if it cannot be audited.

## 4. Sandbox Isolation (The Dead Man's Switch)

PMan never permanently modifies system state.
* **Leased Authority:** Optimizations (e.g., Priority Boosts) are applied as "Leases" (default 5000ms).
* **Automatic Reversion:** If the Agent crashes, hangs, or is terminated by Task Manager, the Leases expire. The OS (or the `RegistryGuard` process) reverts the system to default behavior.
* **Benefit:** A compromised or buggy agent cannot leave the system in a permanently unstable state.

## 5. Privilege & Data

### Administrative Rights
PMan requires Administrator privileges to:
* Manage Process Priorities (`OpenProcess` with `PROCESS_SET_INFORMATION`).
* Manage Services (Suspension/Resumption).
* Read ETW Kernel Traces.

### Data Privacy
* **Local Only:** All learning data (`brain.bin`), logs (`provenance.log`), and profiles are stored locally in `%ProgramData%\PriorityMgr`.
* **No Telemetry:** PMan v5 contains **Zero Telemetry**. It does not report decisions, hardware specs, or user habits to any server.
* **Network:** The only network activity is:
    1.  ICMP Pings to `1.1.1.1` / `8.8.8.8` (Connectivity checks).
    2.  Version check (User initiated via Tray Menu).

## 6. Attack Surface Reduction

* **No Kernel Driver:** PMan runs entirely in User Mode. It cannot cause a Blue Screen of Death (BSOD) directly.
* **Input Sanitization:** The `Investigator` module sanitizes all inputs from the OS (Process Names, Window Titles) before they enter the Decision Engine.
* **Budgeting as Defense:** Even if the internal logic is tricked into "Spamming" optimizations, the `AuthorityBudget` will deplete instantly, locking the agent out of the system.