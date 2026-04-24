package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// sysPkgSpec defines how to detect and query a system package manager.
type sysPkgSpec struct {
	Name       string   // display name: "dnf", "apt", "pacman", "apk"
	Binary     string   // binary to look for in PATH
	VersionCmd []string // command + args to get version (e.g., ["--version"])
	ListCmd    []string // command + args to list installed packages
	ParseLine  func(line string) (name, version string, ok bool)
}

var sysPkgSpecs = []sysPkgSpec{
	{
		// RPM: works on Fedora, RHEL, CentOS, SUSE, Amazon Linux
		Name: "rpm", Binary: "rpm",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"},
		ParseLine:  parseSpaceSeparated,
	},
	{
		// dpkg: works on Debian, Ubuntu, Mint, Pop!_OS
		Name: "dpkg", Binary: "dpkg-query",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-W", "-f", "${Package} ${Version}\n"},
		ParseLine:  parseSpaceSeparated,
	},
	{
		// pacman: Arch Linux, Manjaro, EndeavourOS
		Name: "pacman", Binary: "pacman",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-Q"},
		ParseLine:  parseSpaceSeparated,
	},
	{
		// apk: Alpine Linux
		Name: "apk", Binary: "apk",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"list", "--installed"},
		ParseLine:  parseApkLine,
	},
}

// SystemPkgDetector detects installed system packages on Linux.
type SystemPkgDetector struct {
	exec executor.Executor
}

func NewSystemPkgDetector(exec executor.Executor) *SystemPkgDetector {
	return &SystemPkgDetector{exec: exec}
}

// Detect finds the active system package manager and returns its info.
// Returns nil on non-Linux platforms or if no known PM is found.
func (d *SystemPkgDetector) Detect(ctx context.Context) *model.PkgManager {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	for _, spec := range sysPkgSpecs {
		path, err := d.exec.LookPath(spec.Binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, spec.Binary, spec.VersionCmd...)
		if err == nil && exitCode == 0 {
			if line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0]); line != "" {
				version = line
			}
		}

		return &model.PkgManager{
			Name:    spec.Name,
			Version: version,
			Path:    path,
		}
	}

	return nil
}

// ListPackages returns all installed system packages.
// Uses the first detected package manager from sysPkgSpecs.
func (d *SystemPkgDetector) ListPackages(ctx context.Context) []model.SystemPackage {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	for _, spec := range sysPkgSpecs {
		if _, err := d.exec.LookPath(spec.Binary); err != nil {
			continue
		}

		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 60*time.Second, spec.Binary, spec.ListCmd...)
		if err != nil || exitCode != 0 {
			return nil
		}

		return parsePackageList(stdout, spec.ParseLine)
	}

	return nil
}

func parsePackageList(stdout string, parseLine func(string) (string, string, bool)) []model.SystemPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, ok := parseLine(line)
		if ok {
			packages = append(packages, model.SystemPackage{Name: name, Version: version})
		}
	}
	return packages
}

// DetectAdditionalManagers returns snap and/or flatpak if installed.
// These coexist with the system PM — a machine can have rpm + snap + flatpak.
func (d *SystemPkgDetector) DetectAdditionalManagers(ctx context.Context) []model.PkgManager {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	type additionalPM struct {
		name       string
		binary     string
		versionCmd []string
	}

	candidates := []additionalPM{
		{"snap", "snap", []string{"version"}},
		{"flatpak", "flatpak", []string{"--version"}},
	}

	var managers []model.PkgManager
	for _, pm := range candidates {
		path, err := d.exec.LookPath(pm.binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, pm.binary, pm.versionCmd...)
		if err == nil && exitCode == 0 {
			if line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0]); line != "" {
				version = line
			}
		}

		managers = append(managers, model.PkgManager{
			Name:    pm.name,
			Version: version,
			Path:    path,
		})
	}

	return managers
}

// ListSnapPackages returns installed snap packages.
func (d *SystemPkgDetector) ListSnapPackages(ctx context.Context) []model.SystemPackage {
	if _, err := d.exec.LookPath("snap"); err != nil {
		return nil
	}

	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "snap", "list")
	if err != nil || exitCode != 0 {
		return nil
	}

	// snap list output: "Name  Version  Rev  Tracking  Publisher  Notes"
	// Skip the header line
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			packages = append(packages, model.SystemPackage{Name: fields[0], Version: fields[1]})
		}
	}
	return packages
}

// ListFlatpakPackages returns installed flatpak applications.
func (d *SystemPkgDetector) ListFlatpakPackages(ctx context.Context) []model.SystemPackage {
	if _, err := d.exec.LookPath("flatpak"); err != nil {
		return nil
	}

	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second,
		"flatpak", "list", "--app", "--columns=application,version")
	if err != nil || exitCode != 0 {
		return nil
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "app.id\tversion" (tab-separated)
		parts := strings.SplitN(line, "\t", 2)
		version := "unknown"
		if len(parts) >= 2 && parts[1] != "" {
			version = parts[1]
		}
		if parts[0] != "" {
			packages = append(packages, model.SystemPackage{Name: parts[0], Version: version})
		}
	}
	return packages
}

// parseSpaceSeparated handles "name version" format (rpm, dpkg, pacman).
func parseSpaceSeparated(line string) (string, string, bool) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return parts[0], "unknown", len(parts) == 1 && parts[0] != ""
	}
	return parts[0], parts[1], true
}

// parseApkLine handles apk's "name-version description" format.
// Example: "curl-8.9.1-r2 x86_64 {curl} (MIT)"
func parseApkLine(line string) (string, string, bool) {
	// First token is "name-version-rN arch"
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}
	nameVer := fields[0]

	// Split on last hyphen that separates name from version
	// e.g., "curl-8.9.1-r2" -> "curl", "8.9.1-r2"
	// Alpine packages use "name-version-rRELEASE"
	lastDash := strings.LastIndex(nameVer, "-")
	if lastDash <= 0 {
		return nameVer, "unknown", true
	}
	// Check if what follows the dash starts with a digit (version)
	// If not, look further back
	rest := nameVer[lastDash+1:]
	if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		return nameVer[:lastDash], rest, true
	}
	// Try second-to-last dash
	secondDash := strings.LastIndex(nameVer[:lastDash], "-")
	if secondDash > 0 {
		return nameVer[:secondDash], nameVer[secondDash+1:], true
	}
	return nameVer, "unknown", true
}
