package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestAICLIDetector_FindsClaude(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("claude", "/usr/local/bin/claude")
	mock.SetCommand("1.0.12\n", "", 0, "/usr/local/bin/claude", "--version")
	mock.SetDir("/Users/testuser/.claude")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "claude-code" {
			found = true
			if r.Version != "1.0.12" {
				t.Errorf("expected version 1.0.12, got %s", r.Version)
			}
			if r.BinaryPath != "/usr/local/bin/claude" {
				t.Errorf("expected /usr/local/bin/claude, got %s", r.BinaryPath)
			}
			if r.ConfigDir != "/Users/testuser/.claude" {
				t.Errorf("expected config dir /Users/testuser/.claude, got %s", r.ConfigDir)
			}
			if r.Type != "cli_tool" {
				t.Errorf("expected type cli_tool, got %s", r.Type)
			}
		}
	}
	if !found {
		t.Error("claude-code not found in results")
	}
}

func TestAICLIDetector_NoToolsFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 tools, got %d", len(results))
	}
}

func TestAICLIDetector_VersionUnknown(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("codex", "/usr/local/bin/codex")
	mock.SetCommand("", "", 1, "/usr/local/bin/codex", "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "codex" {
			found = true
			if r.Version != "unknown" {
				t.Errorf("expected unknown, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("codex not found")
	}
}
