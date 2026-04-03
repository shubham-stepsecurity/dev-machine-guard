package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestAgentDetector_FindsOpenclaw(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Users/testuser/.openclaw")
	mock.SetPath("openclaw", "/usr/local/bin/openclaw")
	mock.SetCommand("0.5.2\n", "", 0, "openclaw", "--version")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	found := false
	for _, r := range results {
		if r.Name == "openclaw" {
			found = true
			if r.Type != "general_agent" {
				t.Errorf("expected general_agent, got %s", r.Type)
			}
			if r.InstallPath != "/Users/testuser/.openclaw" {
				t.Errorf("expected /Users/testuser/.openclaw, got %s", r.InstallPath)
			}
		}
	}
	if !found {
		t.Error("openclaw not found")
	}
}

func TestAgentDetector_ClaudeCowork(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.7.5", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	found := false
	for _, r := range results {
		if r.Name == "claude-cowork" {
			found = true
			if r.Vendor != "Anthropic" {
				t.Errorf("expected Anthropic, got %s", r.Vendor)
			}
			if r.Version != "0.7.5" {
				t.Errorf("expected 0.7.5, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("claude-cowork not found")
	}
}

func TestAgentDetector_ClaudeCowork_OldVersion(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.6.9", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewAgentDetector(mock)
	results := det.Detect(context.Background(), []string{"/Users/testuser"})

	for _, r := range results {
		if r.Name == "claude-cowork" {
			t.Error("claude-cowork should not be detected for version 0.6.9")
		}
	}
}

func TestIsCoworkVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"0.7.0", true},
		{"0.7.5", true},
		{"0.9.0", true},
		{"1.0.0", true},
		{"1.5.2", true},
		{"0.6.9", false},
		{"0.1.0", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		got := isCoworkVersion(tt.version)
		if got != tt.want {
			t.Errorf("isCoworkVersion(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}
