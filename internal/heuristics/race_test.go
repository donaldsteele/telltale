//go:build race

package heuristics

// raceEnabled says whether the race detector is on. Code runs several times
// slower under it, so time bounds in tests are scaled (timeBound).
const raceEnabled = true
