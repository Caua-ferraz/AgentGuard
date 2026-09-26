// Package localconfig knows where AgentGuard keeps its files for the
// current user: the config folder (starter policy, API key, what
// `agentguard setup` set up) and the data folder setup creates for the
// audit log and state database. The config folder is the one the
// installers write the starter policy to (scripts/install.sh,
// scripts/install.ps1), so every piece agrees on it.
//
// Functions take the OS as a parameter so tests can check every layout
// from any machine.
package localconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// Names of the files in the config folder.
const (
	PolicyFile = "default.yaml"
	APIKeyFile = "api-key"
	SetupFile  = "setup.json"
)

// ConfigDir is the user's AgentGuard config folder:
// $XDG_CONFIG_HOME/agentguard (else ~/.config/agentguard, on macOS too,
// like the installer), or %APPDATA%\agentguard on Windows. Empty when the
// home folder is unknown.
func ConfigDir(goos string) string {
	if goos == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "agentguard")
		}
		return ""
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "agentguard")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "agentguard")
	}
	return ""
}

// DataDir is where `agentguard setup` keeps the audit log, the state
// database and the server log: $XDG_DATA_HOME/agentguard (else
// ~/.local/share/agentguard), or %LOCALAPPDATA%\AgentGuard\data on Windows.
func DataDir(goos string) string {
	if goos == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "AgentGuard", "data")
		}
		return ""
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "agentguard")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", "agentguard")
	}
	return ""
}

// APIKeyPath is the file `agentguard setup` saves the server's API key in.
func APIKeyPath(goos string) string {
	if d := ConfigDir(goos); d != "" {
		return filepath.Join(d, APIKeyFile)
	}
	return ""
}

// ReadAPIKey returns the key saved by `agentguard setup`, or "" when there
// is none. Client commands fall back to it when neither --api-key nor
// AGENTGUARD_API_KEY is set; the server never reads it implicitly (a key
// changes which interfaces it listens on), only through --api-key-file.
func ReadAPIKey(goos string) string {
	p := APIKeyPath(goos)
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return FirstLine(b)
}

// FirstLine is the first line of b without surrounding whitespace: how a
// key file is read, so a trailing newline from an editor doesn't count.
func FirstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
