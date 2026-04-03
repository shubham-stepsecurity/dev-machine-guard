package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type frameworkSpec struct {
	Name        string
	BinaryName  string
	ProcessName string
}

var frameworkDefinitions = []frameworkSpec{
	{"ollama", "ollama", "ollama"},
	{"localai", "local-ai", "local-ai"},
	{"lm-studio", "lm-studio", "lm-studio"},
	{"text-generation-webui", "textgen", "textgen"},
}

// FrameworkDetector detects AI frameworks and runtimes.
type FrameworkDetector struct {
	exec executor.Executor
}

func NewFrameworkDetector(exec executor.Executor) *FrameworkDetector {
	return &FrameworkDetector{exec: exec}
}

func (d *FrameworkDetector) Detect(ctx context.Context) []model.AITool {
	var results []model.AITool

	for _, spec := range frameworkDefinitions {
		binaryPath, err := d.exec.LookPath(spec.BinaryName)
		if err != nil {
			continue
		}

		version := d.getVersion(ctx, binaryPath)
		isRunning := d.isProcessRunning(ctx, spec.ProcessName)

		results = append(results, model.AITool{
			Name:       spec.Name,
			Vendor:     "Unknown",
			Type:       "framework",
			Version:    version,
			BinaryPath: binaryPath,
			IsRunning:  &isRunning,
		})
	}

	// LM Studio as a GUI application
	if tool, ok := d.detectLMStudioApp(ctx); ok {
		// Avoid duplicating if already found via binary
		found := false
		for _, r := range results {
			if r.Name == "lm-studio" {
				found = true
				break
			}
		}
		if !found {
			results = append(results, tool)
		}
	}

	return results
}

func (d *FrameworkDetector) getVersion(ctx context.Context, binaryPath string) string {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, "--version")
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(stdout, "\n", 2)
	if len(lines) > 0 {
		v := strings.TrimSpace(lines[0])
		if v != "" {
			return v
		}
	}
	return "unknown"
}

func (d *FrameworkDetector) isProcessRunning(ctx context.Context, processName string) bool {
	_, _, exitCode, _ := d.exec.Run(ctx, "pgrep", "-x", processName)
	return exitCode == 0
}

func (d *FrameworkDetector) detectLMStudioApp(ctx context.Context) (model.AITool, bool) {
	appPath := "/Applications/LM Studio.app"
	if !d.exec.DirExists(appPath) {
		return model.AITool{}, false
	}

	version := readPlistVersion(ctx, d.exec, appPath+"/Contents/Info.plist")

	isRunning := false
	_, _, exitCode, _ := d.exec.Run(ctx, "pgrep", "-f", "LM Studio")
	if exitCode == 0 {
		isRunning = true
	}

	return model.AITool{
		Name:       "lm-studio",
		Vendor:     "LM Studio",
		Type:       "framework",
		Version:    version,
		BinaryPath: appPath,
		IsRunning:  &isRunning,
	}, true
}
