//go:build !race

package diff

// raceEnabled says whether the race detector is on. Code runs several times
// slower under it, so time bounds in tests are scaled (timeBound).
const raceEnabled = false
