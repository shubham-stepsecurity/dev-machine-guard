package detector

import (
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// macOS Eclipse feature directories (fixed paths).
var eclipseFeatureDirsDarwin = []string{
	"/Applications/Eclipse.app/Contents/Eclipse/features",
	"/Applications/Eclipse.app/Contents/Eclipse/dropins",
}

// resolveEclipseFeatureDirs returns the Eclipse feature directories to scan
// for the current platform.
func resolveEclipseFeatureDirs(exec executor.Executor) []string {
	if exec.GOOS() != "windows" {
		return eclipseFeatureDirsDarwin
	}

	// On Windows, Eclipse installs to variable paths. Check the same locations
	// as ideDefinitions and resolve features/dropins under each.
	var dirs []string
	candidates := []string{
		filepath.Join(exec.Getenv("PROGRAMFILES"), "eclipse"),
		`C:\eclipse`,
	}

	// Also check user profile eclipse dirs (Oomph installer)
	userProfile := exec.Getenv("USERPROFILE")
	if userProfile != "" {
		eclipseUserDir := filepath.Join(userProfile, "eclipse")
		if exec.DirExists(eclipseUserDir) {
			entries, err := exec.ReadDir(eclipseUserDir)
			if err == nil {
				for _, e := range entries {
					if e.IsDir() {
						candidates = append(candidates, filepath.Join(eclipseUserDir, e.Name(), "eclipse"))
					}
				}
			}
		}
	}

	for _, base := range candidates {
		if !exec.DirExists(base) {
			continue
		}
		featuresDir := filepath.Join(base, "features")
		if exec.DirExists(featuresDir) {
			dirs = append(dirs, featuresDir)
		}
		dropinsDir := filepath.Join(base, "dropins")
		if exec.DirExists(dropinsDir) {
			dirs = append(dirs, dropinsDir)
		}
	}

	return dirs
}

// eclipseBundledPrefixes are feature ID prefixes that ship as part of the
// base Eclipse platform. Features matching these are tagged as "bundled".
var eclipseBundledPrefixes = []string{
	"org.eclipse.platform",
	"org.eclipse.rcp",
	"org.eclipse.e4.rcp",
	"org.eclipse.equinox.",
	"org.eclipse.help",
	"org.eclipse.justj.",
	"org.eclipse.oomph.",
	"org.eclipse.epp.package.",
}

// DetectEclipsePlugins scans Eclipse installations for plugins.
// Uses detected IDE install paths when available (handles custom install locations).
// On macOS: scans features/dropins directories for id_version.jar files.
// On Windows: parses bundles.info (modern Eclipse uses p2 provisioning,
// not a features directory).
func (d *ExtensionDetector) DetectEclipsePlugins(ides []model.IDE) []model.Extension {
	if d.exec.GOOS() == "windows" {
		return d.detectEclipsePluginsWindows(ides)
	}

	var results []model.Extension
	for _, dir := range resolveEclipseFeatureDirs(d.exec) {
		results = append(results, d.collectEclipseFeatures(dir)...)
	}
	return results
}

// detectEclipsePluginsWindows finds Eclipse install directories and parses
// bundles.info for installed plugins. Uses the detected IDE install paths
// (which may have been discovered via registry) so custom paths are covered.
func (d *ExtensionDetector) detectEclipsePluginsWindows(ides []model.IDE) []model.Extension {
	// Collect Eclipse install paths from detected IDEs (registry-aware)
	var eclipseDirs []string
	for _, ide := range ides {
		if ide.IDEType == "eclipse" && ide.InstallPath != "" {
			eclipseDirs = append(eclipseDirs, ide.InstallPath)
		}
	}

	var results []model.Extension
	for _, base := range eclipseDirs {
		bundlesInfo := filepath.Join(base, "configuration", "org.eclipse.equinox.simpleconfigurator", "bundles.info")
		plugins := d.parseEclipseBundlesInfo(bundlesInfo)
		results = append(results, plugins...)
	}
	return results
}

// parseEclipseBundlesInfo reads an Eclipse bundles.info file and returns extensions.
// Format: id,version,location,startLevel,autoStart (one per line, # comments)
func (d *ExtensionDetector) parseEclipseBundlesInfo(filePath string) []model.Extension {
	data, err := d.exec.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 5)
		if len(parts) < 2 {
			continue
		}

		pluginID := parts[0]
		version := parts[1]
		if pluginID == "" || version == "" {
			continue
		}

		publisher := "unknown"
		pubParts := strings.SplitN(pluginID, ".", 3)
		if len(pubParts) >= 2 {
			publisher = pubParts[0] + "." + pubParts[1]
		}

		source := "user_installed"
		if isEclipseBundled(pluginID) {
			source = "bundled"
		}

		results = append(results, model.Extension{
			ID:        pluginID,
			Name:      pluginID,
			Version:   version,
			Publisher: publisher,
			IDEType:   "eclipse",
			Source:    source,
		})
	}

	return results
}

// collectEclipseFeatures reads Eclipse features from a directory.
// Each feature is tagged as "bundled" or "user_installed".
func (d *ExtensionDetector) collectEclipseFeatures(featuresDir string) []model.Extension {
	entries, err := d.exec.ReadDir(featuresDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		name := entry.Name()
		baseName := strings.TrimSuffix(name, ".jar")

		ext := parseEclipsePluginName(baseName)
		if ext == nil {
			continue
		}

		// Tag as bundled or user_installed
		if isEclipseBundled(ext.ID) {
			ext.Source = "bundled"
		} else {
			ext.Source = "user_installed"
		}

		path := filepath.Join(featuresDir, name)
		info, err := d.exec.Stat(path)
		if err == nil {
			ext.InstallDate = info.ModTime().Unix()
		}

		results = append(results, *ext)
	}

	return results
}

func isEclipseBundled(pluginID string) bool {
	for _, prefix := range eclipseBundledPrefixes {
		if strings.HasPrefix(pluginID, prefix) {
			return true
		}
	}
	return false
}

// parseEclipsePluginName parses "id_version" format.
// Example: "com.github.spotbugs.plugin.eclipse_4.9.8.r202510181643-c1fa7f2"
//
//	→ id=com.github.spotbugs.plugin.eclipse, version=4.9.8.r202510181643-c1fa7f2
func parseEclipsePluginName(name string) *model.Extension {
	lastUnderscore := -1
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '_' {
			if i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
				lastUnderscore = i
				break
			}
		}
	}

	if lastUnderscore < 1 {
		return nil
	}

	pluginID := name[:lastUnderscore]
	version := name[lastUnderscore+1:]

	if pluginID == "" || version == "" {
		return nil
	}

	publisher := "unknown"
	parts := strings.SplitN(pluginID, ".", 3)
	if len(parts) >= 2 {
		publisher = parts[0] + "." + parts[1]
	}

	return &model.Extension{
		ID:        pluginID,
		Name:      pluginID,
		Version:   version,
		Publisher: publisher,
		IDEType:   "eclipse",
	}
}
