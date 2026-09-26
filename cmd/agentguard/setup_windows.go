//go:build windows

package main

import (
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// removeFromUserPath takes dir out of the user's PATH (the entry
// install.ps1 added) and tells running programs the environment changed.
// Only that exact entry goes; every other one stays as it was. Reports
// whether it was there.
func removeFromUserPath(dir string) (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer func() { _ = k.Close() }()
	value, kind, err := k.GetStringValue("Path")
	if err != nil {
		return false, nil // no user PATH at all
	}
	parts := strings.Split(value, ";")
	kept := parts[:0]
	found := false
	for _, p := range parts {
		if p == dir {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return false, nil
	}
	joined := strings.Join(kept, ";")
	if kind == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", joined)
	} else {
		err = k.SetStringValue("Path", joined)
	}
	if err != nil {
		return true, err
	}
	broadcastEnvironmentChange()
	return true, nil
}

// broadcastEnvironmentChange is what [Environment]::SetEnvironmentVariable
// does after writing: new terminals opened from Explorer see the change.
func broadcastEnvironmentChange() {
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001A, 0x0002
	var result uintptr
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	_, _, _ = proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}

// deleteAfterExit removes files a running program can't delete itself
// (its own .exe, or one another program still runs) once this process has
// exited, then the folders if they are empty: a hidden cmd waits a few
// seconds and deletes them.
func deleteAfterExit(files, dirs []string) error {
	script := "ping -n 4 127.0.0.1 >nul"
	for _, f := range files {
		script += ` & del /f /q "` + f + `"`
	}
	for _, d := range dirs {
		script += ` & rmdir "` + d + `" 2>nul`
	}
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       `cmd.exe /d /s /c "` + script + `"`,
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd.Start()
}
