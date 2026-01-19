# Contributing to PMan

## Coding Guidelines

### 1. Resource Management (RAII)
**Strictly Enforced.** Never use raw `CloseHandle`, `RegCloseKey`, or `delete`.
- Use `UniqueHandle` for HANDLEs.
- Use `UniqueRegKey` for HKEYs.
- Use `std::unique_ptr` for heap allocations.

### 2. No Loose Globals
Do not declare global variables in `globals.h`.
- Use the `PManContext` singleton for application state.
- Use `std::atomic` for any variable shared between the UI thread and worker threads.

### 3. Windows API Abstraction
Do not call `GetProcAddress` or internal NT APIs directly in business logic.
- Use `NtWrapper` (`include/nt_wrapper.h`) for all `Nt*` functions.
- Check `OSCapabilities` (`g_caps`) before using version-specific features (e.g., Power Throttling, EcoQoS).

### 4. Safety First
- **Zero Risk:** Optimizations must never risk BSOD or data loss.
- **Registry Caching:** Always use `RegWriteDwordCached` to prevent registry hammering.
- **Verification:** Every optimization function must verify the process is still alive before applying changes.