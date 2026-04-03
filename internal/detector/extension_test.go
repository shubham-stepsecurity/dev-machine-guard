package detector

import (
	"testing"
)

func TestParseExtensionDir_Valid(t *testing.T) {
	tests := []struct {
		dirname   string
		publisher string
		name      string
		version   string
	}{
		{"ms-python.python-2024.22.0", "ms-python", "python", "2024.22.0"},
		{"esbenp.prettier-vscode-10.4.0", "esbenp", "prettier-vscode", "10.4.0"},
		{"dbaeumer.vscode-eslint-3.0.10", "dbaeumer", "vscode-eslint", "3.0.10"},
	}

	for _, tt := range tests {
		ext := parseExtensionDir(tt.dirname, "vscode")
		if ext == nil {
			t.Errorf("parseExtensionDir(%q) returned nil", tt.dirname)
			continue
		}
		if ext.Publisher != tt.publisher {
			t.Errorf("publisher: expected %s, got %s", tt.publisher, ext.Publisher)
		}
		if ext.Name != tt.name {
			t.Errorf("name: expected %s, got %s", tt.name, ext.Name)
		}
		if ext.Version != tt.version {
			t.Errorf("version: expected %s, got %s", tt.version, ext.Version)
		}
	}
}

func TestParseExtensionDir_PlatformSuffix(t *testing.T) {
	ext := parseExtensionDir("ms-python.python-2024.22.0-darwin-arm64", "vscode")
	if ext == nil {
		t.Fatal("expected non-nil")
	}
	if ext.Version != "2024.22.0" {
		t.Errorf("expected 2024.22.0, got %s", ext.Version)
	}
}

func TestParseExtensionDir_Universal(t *testing.T) {
	ext := parseExtensionDir("ms-toolsai.jupyter-2024.5.0-universal", "vscode")
	if ext == nil {
		t.Fatal("expected non-nil")
	}
	if ext.Version != "2024.5.0" {
		t.Errorf("expected 2024.5.0, got %s", ext.Version)
	}
}

func TestParseExtensionDir_Invalid(t *testing.T) {
	tests := []string{
		"nopublisher",
		".nodot-prefix-1.0.0",
		"pub.",
	}
	for _, tt := range tests {
		ext := parseExtensionDir(tt, "vscode")
		if ext != nil {
			t.Errorf("parseExtensionDir(%q) should return nil, got %+v", tt, ext)
		}
	}
}

func TestParseExtensionDir_ID(t *testing.T) {
	ext := parseExtensionDir("ms-python.python-2024.22.0", "vscode")
	if ext == nil {
		t.Fatal("expected non-nil")
	}
	if ext.ID != "ms-python.python" {
		t.Errorf("expected ms-python.python, got %s", ext.ID)
	}
	if ext.IDEType != "vscode" {
		t.Errorf("expected vscode, got %s", ext.IDEType)
	}
}
