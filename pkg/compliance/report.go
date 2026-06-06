package compliance

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/plexar-io/plexar/internal/types"
)

// ExportCSV writes compliance results as CSV
func ExportCSV(w io.Writer, results []types.ComplianceResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"framework", "version", "control_id", "control_name", "status", "violations", "evidence"}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for _, result := range results {
		for _, ctrl := range result.Controls {
			row := []string{
				result.Framework,
				result.Version,
				ctrl.ID,
				ctrl.Name,
				ctrl.Status,
				strconv.Itoa(ctrl.Violations),
				ctrl.Evidence,
			}
			if err := cw.Write(row); err != nil {
				return fmt.Errorf("write row: %w", err)
			}
		}
	}

	return nil
}

// ExportSummary writes a human-readable compliance summary
func ExportSummary(w io.Writer, results []types.ComplianceResult) {
	for _, result := range results {
		fmt.Fprintf(w, "\n  %s  %s  %d%%  %d/%d controls passing\n",
			result.Framework, result.Version, result.Score, result.Passing, result.TotalChecks)
		for _, ctrl := range result.Controls {
			icon := "✓"
			if ctrl.Status == "fail" {
				icon = "✗"
			} else if ctrl.Status == "warn" {
				icon = "⚠"
			}
			fmt.Fprintf(w, "    %s %s  %s", icon, ctrl.ID, ctrl.Name)
			if ctrl.Violations > 0 {
				fmt.Fprintf(w, " (%d violations)", ctrl.Violations)
			}
			fmt.Fprintln(w)
		}
	}
}
