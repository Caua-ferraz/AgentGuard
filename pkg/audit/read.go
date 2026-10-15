package audit

// read.go — reading a whole audit log, rotated archives included, for tools
// that report on it (`agentguard report`). It walks the same files
// VerifyChain checks and scans them with the startup replay's scanner, so a
// report and a verify of one log always look at the same entries.

import "os"

// LogFiles returns the audit log at livePath and the rotated archives (gzip
// or plain) that link back to it through _meta.rotated_from, oldest first:
// the files VerifyChain checks. An archive that no file links to is left
// out; VerifyChain reports it. The error is for a live file that can't be
// read.
func LogFiles(livePath string) ([]string, error) {
	if _, err := os.Stat(livePath); err != nil {
		return nil, err
	}
	files, _, _ := chainFiles(livePath)
	return files, nil
}

// ReadEntries calls fn for every entry of one audit file (the live file or
// a rotated archive, gzip or plain), in file order. It skips blank and
// _meta lines and returns how many lines were not valid entries; nothing is
// logged for them. The error is for a file that can't be opened or read to
// the end (a damaged gzip stream, say); the entries before that point have
// already been passed to fn.
func ReadEntries(path string, fn func(Entry)) (bad int, err error) {
	err = scanFile(path, 0, fn, func(error) { bad++ })
	return bad, err
}
