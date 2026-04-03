package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestIDEDetector_FindsVSCode(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Visual Studio Code.app")
	mock.SetFile("/Applications/Visual Studio Code.app/Contents/Info.plist", []byte{})
	mock.SetCommand("1.96.0\n", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Visual Studio Code.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].IDEType != "vscode" {
		t.Errorf("expected vscode, got %s", results[0].IDEType)
	}
	if results[0].Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", results[0].Version)
	}
	if results[0].Vendor != "Microsoft" {
		t.Errorf("expected Microsoft, got %s", results[0].Vendor)
	}
	if !results[0].IsInstalled {
		t.Error("expected is_installed=true")
	}
}

func TestIDEDetector_NotInstalled(t *testing.T) {
	mock := executor.NewMock()
	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 IDEs, got %d", len(results))
	}
}

func TestIDEDetector_VersionFromBinary(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Cursor.app")
	mock.SetFile("/Applications/Cursor.app/Contents/Resources/app/bin/cursor", []byte{})
	mock.SetCommand("0.50.1\n1234abcd\nx64", "", 0, "/Applications/Cursor.app/Contents/Resources/app/bin/cursor", "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].Version != "0.50.1" {
		t.Errorf("expected 0.50.1, got %s", results[0].Version)
	}
}

func TestIDEDetector_MultipleIDEs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Visual Studio Code.app")
	mock.SetFile("/Applications/Visual Studio Code.app/Contents/Info.plist", []byte{})
	mock.SetCommand("1.96.0", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Visual Studio Code.app/Contents/Info.plist")

	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.7.1", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 IDEs, got %d", len(results))
	}
}
