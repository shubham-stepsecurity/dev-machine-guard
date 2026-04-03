package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestNodePMDetector_FindsNPM(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) < 1 {
		t.Fatal("expected at least 1 package manager")
	}
	if results[0].Name != "npm" {
		t.Errorf("expected npm, got %s", results[0].Name)
	}
	if results[0].Version != "10.2.0" {
		t.Errorf("expected 10.2.0, got %s", results[0].Version)
	}
}

func TestNodePMDetector_Multiple(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	mock.SetPath("yarn", "/usr/local/bin/yarn")
	mock.SetCommand("1.22.19\n", "", 0, "yarn", "--version")

	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 package managers, got %d", len(results))
	}
}

func TestNodePMDetector_NoneFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewNodePMDetector(mock)
	results := det.DetectManagers(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 package managers, got %d", len(results))
	}
}

func TestDetectProjectPM(t *testing.T) {
	mock := executor.NewMock()

	tests := []struct {
		name     string
		setup    func()
		expected string
	}{
		{
			name: "bun lock",
			setup: func() {
				mock.SetFile("/project/bun.lock", []byte{})
			},
			expected: "bun",
		},
		{
			name: "pnpm lock",
			setup: func() {
				mock.SetFile("/project/pnpm-lock.yaml", []byte{})
			},
			expected: "pnpm",
		},
		{
			name: "yarn lock",
			setup: func() {
				mock.SetFile("/project/yarn.lock", []byte{})
			},
			expected: "yarn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := executor.NewMock()
			tt.setup = func() {} // reset
			// Need fresh mock for isolation
			freshMock := executor.NewMock()
			switch tt.expected {
			case "bun":
				freshMock.SetFile("/project/bun.lock", []byte{})
			case "pnpm":
				freshMock.SetFile("/project/pnpm-lock.yaml", []byte{})
			case "yarn":
				freshMock.SetFile("/project/yarn.lock", []byte{})
			}
			_ = m
			got := DetectProjectPM(freshMock, "/project")
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}
