package apidump

import "fmt"

// checkImplementedModes refuses the values of --https-capture-mode and
// --privacy-mode that are planned but not implemented, so that a run never
// silently ignores them: --privacy-mode=strict, for example, would otherwise
// capture as 'standard' does.
func checkImplementedModes(captureMode, privacy string) error {
	if captureMode != "truncated" {
		return fmt.Errorf("--https-capture-mode=%s is not implemented; only 'truncated' is", captureMode)
	}
	if privacy != "standard" {
		return fmt.Errorf("--privacy-mode=%s is not implemented; only 'standard' is", privacy)
	}
	return nil
}
