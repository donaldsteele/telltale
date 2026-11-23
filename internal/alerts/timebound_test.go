package alerts

import "time"

// timeBound is a time limit for a test that catches work growing faster
// than it should: d, or ten times d under the race detector, which slows
// everything down. The inputs stay the same size, so a blowup still fails.
func timeBound(d time.Duration) time.Duration {
	if raceEnabled {
		return 10 * d
	}
	return d
}
