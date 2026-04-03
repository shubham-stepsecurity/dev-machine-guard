package lock

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const lockFilePath = "/tmp/stepsecurity-dev-machine-guard.lock"

// Lock represents an acquired instance lock.
type Lock struct {
	path string
}

// Acquire obtains an exclusive instance lock. Returns error if another instance is running.
func Acquire(exec executor.Executor) (*Lock, error) {
	// Check for existing lock
	if data, err := os.ReadFile(lockFilePath); err == nil {
		pidStr := strings.TrimSpace(string(data))
		if pid, err := strconv.Atoi(pidStr); err == nil {
			// Check if the process is still alive
			if err := syscall.Kill(pid, 0); err == nil {
				return nil, fmt.Errorf("another instance is already running (PID %d)", pid)
			}
		}
		// Stale lock file, remove it
		os.Remove(lockFilePath)
	}

	// Write our PID
	pid := os.Getpid()
	if err := os.WriteFile(lockFilePath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return nil, fmt.Errorf("creating lock file: %w", err)
	}

	return &Lock{path: lockFilePath}, nil
}

// Release removes the lock file.
func (l *Lock) Release() {
	if l != nil && l.path != "" {
		os.Remove(l.path)
	}
}
