#ifndef PMAN_STATIC_TWEAKS_H
#define PMAN_STATIC_TWEAKS_H

// Executes the list of one-time system optimizations.
// Uses native Windows APIs to avoid AV detection (no cmd/reg.exe).
void ApplyStaticTweaks();

#endif // PMAN_STATIC_TWEAKS_H