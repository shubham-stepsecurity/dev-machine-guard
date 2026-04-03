package output

import (
	"encoding/json"
	"io"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// JSON writes the scan result as formatted JSON to the given writer.
func JSON(w io.Writer, result *model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(result)
}
