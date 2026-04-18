package migrate

// ResetForTest clears the migration registry. Production code must never call
// this — migrations are immutable once registered — but tests that Register()
// a fake Migration need a way to tear down between runs.
func ResetForTest() { resetRegistry() }
