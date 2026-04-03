package device

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Gather collects device information (hostname, serial, OS version, user identity).
func Gather(ctx context.Context, exec executor.Executor) model.Device {
	hostname, _ := exec.Hostname()
	serial := getSerialNumber(ctx, exec)
	osVersion := getOSVersion(ctx, exec)
	userIdentity := getDeveloperIdentity(exec)

	return model.Device{
		Hostname:     hostname,
		SerialNumber: serial,
		OSVersion:    osVersion,
		Platform:     "darwin",
		UserIdentity: userIdentity,
	}
}

func getSerialNumber(ctx context.Context, exec executor.Executor) string {
	// Try ioreg first
	stdout, _, _, err := exec.Run(ctx, "ioreg", "-l")
	if err == nil {
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					serial := strings.TrimSpace(parts[1])
					serial = strings.Trim(serial, "\" ")
					if serial != "" {
						return serial
					}
				}
			}
		}
	}

	// Fallback: system_profiler
	stdout, _, _, err = exec.Run(ctx, "system_profiler", "SPHardwareDataType")
	if err == nil {
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "Serial") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					serial := strings.TrimSpace(parts[1])
					if serial != "" {
						return serial
					}
				}
			}
		}
	}

	return "unknown"
}

func getOSVersion(ctx context.Context, exec executor.Executor) string {
	stdout, _, _, err := exec.Run(ctx, "sw_vers", "-productVersion")
	if err == nil {
		v := strings.TrimSpace(stdout)
		if v != "" {
			return v
		}
	}
	return "unknown"
}

func getDeveloperIdentity(exec executor.Executor) string {
	// Check environment variables in order of preference
	for _, key := range []string{"USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"} {
		if v := exec.Getenv(key); v != "" {
			return v
		}
	}
	// Fallback to current username
	u, err := exec.CurrentUser()
	if err == nil {
		return u.Username
	}
	return "unknown"
}
