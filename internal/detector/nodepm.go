package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type pmSpec struct {
	Name       string
	Binary     string
	VersionCmd string
}

var packageManagers = []pmSpec{
	{"npm", "npm", "--version"},
	{"yarn", "yarn", "--version"},
	{"pnpm", "pnpm", "--version"},
	{"bun", "bun", "--version"},
}

// NodePMDetector detects installed Node.js package managers.
type NodePMDetector struct {
	exec executor.Executor
}

func NewNodePMDetector(exec executor.Executor) *NodePMDetector {
	return &NodePMDetector{exec: exec}
}

func (d *NodePMDetector) DetectManagers(ctx context.Context) []model.PkgManager {
	var results []model.PkgManager

	for _, pm := range packageManagers {
		path, err := d.exec.LookPath(pm.Binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, pm.Binary, pm.VersionCmd)
		if err == nil {
			v := strings.TrimSpace(stdout)
			if v != "" {
				version = v
			}
		}

		results = append(results, model.PkgManager{
			Name:    pm.Name,
			Version: version,
			Path:    path,
		})
	}

	return results
}
