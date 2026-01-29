# Security Scope

PMan is a local-system performance utility. All processing occurs entirely on the host machine, with specific exceptions for network connectivity checks and optional updates.

## Privilege Model

### Administrative Rights
Required for full functionality:
* Modifying `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl`
* Suspending/resuming Windows services (BITS, wuauserv, dosvc)
* Setting process I/O priority via `NtSetInformationProcess`
* Enabling GPU hardware scheduling
* Creating system restore points

**Without admin rights:**
* Falls back to read-only monitoring
* Logs warnings for skipped operations
* Still classifies processes and logs recommendations
* No registry writes or service modifications

### Standard User Rights
Tray UI and log viewing function without elevation. However, **Real-time ETW monitoring (Kernel Logger) requires Administrator privileges** or membership in the 'Performance Log Users' group to function. The startup task is configured to run elevated via Task Scheduler.

## Data Handling

### Local Storage
* **Log Files:** Written to `%ProgramData%\PriorityMgr\log.txt`. Permissions rely on standard Windows directory inheritance (typically allowing Read/Write to the creating user/admin).
* **Configuration:** INI files stored in the same directory.
* **Game Profiles:** Binary `profiles.bin` file with process names and performance metrics; no PII.
* **Registry:** Only modifies performance-related keys under `HKLM\SYSTEM` and `HKCU\SOFTWARE`; never touches credential or security policy keys.

### Network Activity
* **Connectivity Probes:** The Network Monitor autonomously sends ICMP Echo Requests (Pings) to public endpoints (1.1.1.1 and 8.8.8.8) to detect network instability. No application data is transmitted in these probes.
* **Update Check:** Manual, user-initiated from tray menu. Uses ShellExecute to open the project's GitHub Releases page in the default web browser. The application does not perform background network requests or auto-download binaries.
* **No Telemetry:** No usage data, metrics, or system information is uploaded or transmitted to any remote server.

### Process Access
PMan opens target processes with the minimum required access rights for its features:
* `PROCESS_QUERY_LIMITED_INFORMATION` for classification and identity verification.
* `PROCESS_SET_INFORMATION` for priority/affinity adjustments.
* `PROCESS_SET_QUOTA` for working set management.
* `PROCESS_VM_READ` is requested strictly for gathering memory statistics (via `GetProcessMemoryInfo` in the Memory Optimizer).
* **Restriction:** PMan does **not** request `PROCESS_VM_WRITE` and performs no code injection.

## Attack Surface Analysis

### File Parsing
* **Config INI files:** Parsed with manual line scanning, not generic deserialization. Validates executable names via `IsValidExecutableName()` which enforces `.exe` extension, length limits, and reserved name blacklisting.
* **Binary profiles:** Header magic `0x504D414E` and version field validated before reading. Size prefix used to prevent buffer overruns.

### Registry Operations
* **Write Protection:** All registry writes check `g_caps.hasAdminRights` and log failures without crashing.
* **Value Validation:** Numeric values are range-checked (e.g., timer resolution clamped). String values are length-limited.
* **Restore on Exit:** `g_restoreOnExit` (default true) ensures values are restored via a separate guard process even if the main thread crashes.

### Service Control
* **Whitelisting:** Only predefined services (BITS, wuauserv, etc.) are eligible for suspension. Critical services are hard-coded in `IsCriticalService()` and blocked from `ControlService` operations.
* **Dependency Check:** `EnumDependentServicesW` prevents suspending services with active dependents.
* **Timeout Protection:** Service operations abort after 5 seconds to avoid deadlock.

### Process Injection Risk
* **No code injection:** PMan does not use `CreateRemoteThread`, `WriteProcessMemory`, or similar injection APIs. All optimizations are applied via documented Windows APIs that the OS handles safely.

## Known Security Limitations
* **Local Privilege Escalation:** If run as admin, a compromised PMan process could suspend security services. This is hardened by the critical service whitelist, but users should manually restrict write permissions on `%ProgramData%\PriorityMgr` in multi-user environments.
* **Denial of Service:** Malformed config files could cause high CPU usage during parsing. Mitigated by 1-second reload debounce and size limits on all containers.
* **Log Injection:** User-controlled process names are logged. The Log viewer runs in the context of the local user and treats content as plain text.

## Safe Operation Guidelines
* Run PMan only from trusted directories (e.g., `%ProgramFiles%`).
* Protect `%ProgramData%\PriorityMgr` from unauthorized write access if multi-user isolation is required.
* Review `ignore_processes.txt` after installation to ensure system-specific critical processes are listed.
* Use "Pause Activity" before running security-sensitive applications (e.g., financial software).
* Do not add user services to suspension lists; use the built-in operational whitelist only.

## Vulnerability Disclosure
Please report security vulnerabilities by contacting the maintainer with:
* Steps to reproduce
* Expected vs. actual behavior
* Impact assessment (confidentiality, integrity, availability)

**Response Timeline:** Within 30 days for initial acknowledgment. No formal bug bounty program exists.