#ifndef PMAN_RESTORE_H
#define PMAN_RESTORE_H

// Checks if a restore point has been created for this version/installation.
// If not, attempts to create one and marks the flag in the registry.
void EnsureStartupRestorePoint();

#endif // PMAN_RESTORE_H
