# Design Rationale & Implementation Trade-offs

## Core Philosophy: Sovereignty with Accountability

In **PMan v5**, we shifted from a "Tool" paradigm (user clicks button, tool acts) to an **"Agent" paradigm** (system observes, thinks, and acts).

The core design challenge was: *How do we give software the authority to modify kernel priorities without creating a runaway process that destabilizes the OS?*

**Solution:** The system is designed as a **Licensed Operator**. It has a "Budget" of authority. It must "pay" for every intervention, and if it runs out of budget or confidence, it is physically locked out of making changes.

---

## 1. The "Shadow First" Execution Model

**Problem:** Traditional optimizers apply a tweak (e.g., "Set High Priority") and hope it works. If it causes stutter, the user notices it *after* the damage is done.

**Design:** **Shadow Execution Layer** (`ShadowExecutor`)
Before applying any change, PMan runs a simulation:
1.  **Snapshot:** Captures current CPU Variance and Latency.
2.  **Predict:** Uses the internal `PredictiveModel` to estimate the state *delta* if the action were taken.
3.  **Gate:** If the predicted benefit is lower than the `MinConfidence` threshold, the action is rejected *before* touching the OS.

**Trade-off:** This adds ~50-100µs of computational overhead per decision tick, but prevents "thrashing" (rapidly toggling states) which is the #1 cause of micro-stutter in optimization tools.

---

## 2. Authority Budgeting vs. Rate Limiting

**Old Approach:** Simple Rate Limiting (e.g., "Don't change priority more than once every 5 seconds").
**New Approach:** **Authority Budget** (`AuthorityBudget`)

We model system intervention as a scarce economic resource:
* **Income:** The budget regenerates slowly over time (Time Decay).
* **Cost:**
    * `Throttle_Mild`: Cheap (Low Risk).
    * `Boost_Process`: Expensive (High Risk of Starvation).
    * `Suspend_Service`: Very Expensive.

**Rationale:** Rate limits prevents fast toggling, but they don't prevent *bad decisions*. A Budget prevents **cumulative fatigue**. If the Agent tries to fix the system 10 times in a minute and fails, it bankrupts itself and stops acting. This prevents "Optimizer Wars" where PMan fights another tool or the OS.

---

## 3. The "Lease" Mechanism (Crash Safety)

**Problem:** If PMan boosts a game to `REALTIME_PRIORITY_CLASS` and then crashes, the system might hang indefinitely.

**Design:** **Time-Bound Leases** (`SandboxExecutor`)
PMan never "sets" a priority. It "leases" it.
1.  PMan applies `HIGH_PRIORITY`.
2.  It records a timestamp (`LeaseStart`).
3.  On the next tick (e.g., +1000ms), if the logic does not explicitly **Renew** the lease, the Sandbox *automatically* reverts the change.

**Rationale:** This creates a "Dead Man's Switch." If the cognitive loop hangs, crashes, or gets stuck, the optimizations expire and the system naturally returns to Windows defaults.

---

## 4. Provenance & Counterfactuals

**Problem:** When an autonomous system makes a decision, it is often a "Black Box." Users don't know *why* it boosted Edge but throttled Spotify.

**Design:** **Provenance Ledger**
We record not just the Action, but the **Counterfactuals** (The road not taken).
* *Record:* "Selected Action: `Optimize_Memory`."
* *Counterfactual:* "Rejected `Boost_Process` because `Confidence (0.4) < Threshold (0.7)`."
* *Counterfactual:* "Rejected `Throttle_Mild` because `Budget (5) < Cost (10)`."

**Rationale:** Trust requires transparency. By logging *why* we didn't act, users can tune the `policy.json` (e.g., increasing the budget) if they want a more aggressive agent.

---

## 5. Universal Defender Cooperation (DCM)

**Problem:** Most optimizers fight Windows Defender (`MsMpEng.exe`), treating its CPU spikes as "background noise" to be throttled. This causes scans to take longer, prolonging the disk contention.

**Design:** **"Shield, Don't Fight"**
When PMan detects high pressure from a Security process:
1.  It identifies the `DominantPressure` as `Security`.
2.  It enters `SystemMode::Interactive` (to protect the user).
3.  It explicitly **Whitelists** the AV process, refusing to throttle it.

**Rationale:** Security operations are inevitable. The fastest way to end a virus scan is to let it finish. Throttling it only drags out the performance hit.

---

## 6. Implementation Trade-offs

| Feature | Design Choice | Trade-off |
| :--- | :--- | :--- |
| **Observation** | **SRAM (Sidecar Thread)** | Uses ~0.5% CPU to actively ping the UI thread. Essential for measuring *human* lag, but slightly increases idle load. |
| **Process Scan** | **Diff-Scanning** | Instead of scanning 400 processes every tick, we rely on ETW process start/stop events. Full scans only happen on `ConfigReload`. |
| **Memory** | **Hard Limits** | The `ProvenanceLedger` is a ring buffer. We lose history after N records to ensure PMan never consumes >50MB RAM. |
| **Kernel** | **User-Mode Only** | We explicitly reject Kernel Drivers. This limits our ability to control thread scheduling quantum, but guarantees we never BSOD the system. |