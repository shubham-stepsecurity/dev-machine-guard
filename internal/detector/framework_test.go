package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestFrameworkDetector_FindsOllama(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("ollama", "/usr/local/bin/ollama")
	mock.SetCommand("0.5.4\n", "", 0, "/usr/local/bin/ollama", "--version")
	mock.SetCommand("12345\n", "", 0, "pgrep", "-x", "ollama")

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "ollama" {
			found = true
			if r.Type != "framework" {
				t.Errorf("expected framework, got %s", r.Type)
			}
			if r.IsRunning == nil || !*r.IsRunning {
				t.Error("expected is_running=true")
			}
		}
	}
	if !found {
		t.Error("ollama not found")
	}
}

func TestFrameworkDetector_NotRunning(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("ollama", "/usr/local/bin/ollama")
	mock.SetCommand("0.5.4\n", "", 0, "/usr/local/bin/ollama", "--version")
	mock.SetCommand("", "", 1, "pgrep", "-x", "ollama") // not running

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "ollama" {
			if r.IsRunning == nil || *r.IsRunning {
				t.Error("expected is_running=false")
			}
		}
	}
}

func TestFrameworkDetector_LMStudioApp(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/LM Studio.app")
	mock.SetFile("/Applications/LM Studio.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.3.1", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/LM Studio.app/Contents/Info.plist")
	mock.SetCommand("", "", 1, "pgrep", "-f", "LM Studio") // not running

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "lm-studio" {
			found = true
			if r.Version != "0.3.1" {
				t.Errorf("expected 0.3.1, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("lm-studio not found")
	}
}
