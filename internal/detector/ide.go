package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type ideSpec struct {
	AppName      string
	IDEType      string
	Vendor       string
	AppPath      string
	BinaryPath   string // relative to AppPath
	VersionFlag  string
}

var ideDefinitions = []ideSpec{
	{"Visual Studio Code", "vscode", "Microsoft", "/Applications/Visual Studio Code.app", "Contents/Resources/app/bin/code", "--version"},
	{"Cursor", "cursor", "Cursor", "/Applications/Cursor.app", "Contents/Resources/app/bin/cursor", "--version"},
	{"Windsurf", "windsurf", "Codeium", "/Applications/Windsurf.app", "Contents/MacOS/Windsurf", "--version"},
	{"Antigravity", "antigravity", "Google", "/Applications/Antigravity.app", "Contents/MacOS/Antigravity", "--version"},
	{"Zed", "zed", "Zed", "/Applications/Zed.app", "Contents/MacOS/zed", ""},
	{"Claude", "claude_desktop", "Anthropic", "/Applications/Claude.app", "", ""},
	{"Microsoft Copilot", "microsoft_copilot_desktop", "Microsoft", "/Applications/Copilot.app", "", ""},
}

// IDEDetector detects installed IDEs and AI desktop apps.
type IDEDetector struct {
	exec executor.Executor
}

func NewIDEDetector(exec executor.Executor) *IDEDetector {
	return &IDEDetector{exec: exec}
}

func (d *IDEDetector) Detect(ctx context.Context) []model.IDE {
	var results []model.IDE

	for _, spec := range ideDefinitions {
		if !d.exec.DirExists(spec.AppPath) {
			continue
		}

		version := "unknown"

		// Try version from binary
		if spec.BinaryPath != "" && spec.VersionFlag != "" {
			binaryFull := spec.AppPath + "/" + spec.BinaryPath
			if d.exec.FileExists(binaryFull) {
				stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryFull, spec.VersionFlag)
				if err == nil {
					lines := strings.SplitN(stdout, "\n", 2)
					if len(lines) > 0 {
						v := strings.TrimSpace(lines[0])
						if v != "" {
							version = v
						}
					}
				}
			}
		}

		// Fallback: Info.plist
		if version == "unknown" {
			version = readPlistVersion(ctx, d.exec, spec.AppPath+"/Contents/Info.plist")
		}

		results = append(results, model.IDE{
			IDEType:     spec.IDEType,
			Version:     version,
			InstallPath: spec.AppPath,
			Vendor:      spec.Vendor,
			IsInstalled: true,
		})
	}

	return results
}

// readPlistVersion reads CFBundleShortVersionString from an Info.plist.
func readPlistVersion(ctx context.Context, exec executor.Executor, plistPath string) string {
	if !exec.FileExists(plistPath) {
		return "unknown"
	}
	stdout, _, _, err := exec.Run(ctx, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plistPath)
	if err == nil {
		v := strings.TrimSpace(stdout)
		if v != "" {
			return v
		}
	}
	return "unknown"
}
