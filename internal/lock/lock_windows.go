//go:build windows

package lock

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var lockFilePath = filepath.Join(os.TempDir(), "stepsecurity-dev-machine-guard.lock")

// isProcessAlive checks if a process with the given PID exists by attempting
// to open a handle to it. This avoids shelling out to tasklist.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}
