//go:build windows

package device

import (
	"context"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// getSerialNumberWindows reads the BIOS serial number from the Windows registry.
// Falls back to the machine GUID if the serial is empty or a placeholder.
func getSerialNumberWindows(_ context.Context, _ executor.Executor) string {
	// Try BIOS registry key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err == nil {
		serial, _, err := k.GetStringValue("SystemSerialNumber")
		_ = k.Close()
		if err == nil && serial != "" && serial != "System Serial Number" && serial != "To Be Filled By O.E.M." {
			return serial
		}
	}

	// Fallback: MachineGuid (unique per install, always present)
	k, err = registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		guid, _, err := k.GetStringValue("MachineGuid")
		_ = k.Close()
		if err == nil && guid != "" {
			return guid
		}
	}

	return "unknown"
}

// getOSVersionWindows returns the Windows version using the native RtlGetVersion API.
func getOSVersionWindows(_ context.Context, _ executor.Executor) string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
