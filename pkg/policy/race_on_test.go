//go:build race

package policy

// raceDetector reports whether the tests run with -race, which slows the
// code down several times; wall-clock bounds scale with it.
const raceDetector = true
