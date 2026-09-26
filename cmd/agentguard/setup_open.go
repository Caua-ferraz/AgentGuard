package main

// setup_open.go: handing things to the desktop — a URL to the browser, the
// policy file to an editor, the API key to the clipboard.

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// openURL opens a URL (or a file) with the desktop's default program.
func openURL(target string) error {
	var cmd *exec.Cmd
	switch goos {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

// editFile opens path in $VISUAL or $EDITOR when one is set (and waits for
// it, since a terminal editor needs the terminal), otherwise with the
// desktop's default program.
func editFile(path string) error {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := strings.Fields(os.Getenv(v)); len(e) > 0 {
			cmd := exec.Command(e[0], append(e[1:], path)...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		}
	}
	if goos == "darwin" {
		return exec.Command("open", "-t", path).Start() // the default text editor
	}
	return openURL(path)
}

// copyToClipboard puts text on the clipboard with the tool the desktop has.
func copyToClipboard(text string) error {
	var candidates [][]string
	switch goos {
	case "windows":
		candidates = [][]string{{"clip.exe"}}
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	default:
		candidates = [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	return errors.New("no clipboard tool found")
}
