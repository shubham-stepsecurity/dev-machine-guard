//go:build windows

package config

import "golang.org/x/sys/windows"

// machineConfigDir is the machine-wide config location on Windows. The
// path is hardcoded (not derived from %PROGRAMDATA%) so it matches what
// the MSI WiX manifest hardcodes — keeping installer and binary in sync.
func machineConfigDir() string {
	return `C:\ProgramData\StepSecurity`
}

// isElevated reports whether the current process holds an elevated token
// (admin rights / UAC-elevated). MSI custom actions running deferred with
// Impersonate=no execute under LocalSystem, which is elevated.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
