package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/boomer/tf-sim/internal/model"
)

// Standard output format constants.
const (
	FormatTable    = "table"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
)

// normalizeFormat validates and canonicalizes the requested output format.
func normalizeFormat(format string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(format))
	switch norm {
	case FormatTable, FormatJSON, FormatMarkdown:
		return norm, nil
	default:
		return "", fmt.Errorf("unsupported output format %q: expected %q, %q, or %q", format, FormatTable, FormatJSON, FormatMarkdown)
	}
}

// FormatVerificationResult formats a static AST verification result across table, json, or markdown formats.
func FormatVerificationResult(res *model.VerificationResult, format string) (string, error) {
	if res == nil {
		return "", fmt.Errorf("verification result cannot be nil")
	}
	norm, err := normalizeFormat(format)
	if err != nil {
		return "", err
	}

	switch norm {
	case FormatJSON:
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling verification result to JSON: %w", err)
		}
		return string(data), nil

	case FormatTable:
		var b strings.Builder
		status := "VALID"
		if !res.Valid {
			status = "INVALID"
		}
		b.WriteString(fmt.Sprintf("Policy:      %s\n", res.PolicyPath))
		b.WriteString(fmt.Sprintf("Package:     %s\n", res.PackageName))
		b.WriteString(fmt.Sprintf("Status:      %s\n", status))
		b.WriteString(fmt.Sprintf("Diagnostics: %d\n", len(res.Diagnostics)))

		if len(res.Diagnostics) > 0 {
			b.WriteString("\n")
			w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SEVERITY\tLINE\tRESOURCE TYPE\tINVALID PATH\tMESSAGE")
			for _, d := range res.Diagnostics {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", d.Severity, d.Line, d.ResourceType, d.InvalidPath, d.Message)
			}
			w.Flush()
		}
		return b.String(), nil

	case FormatMarkdown:
		var b strings.Builder
		statusBadge := "✅ VALID"
		if !res.Valid {
			statusBadge = "❌ INVALID"
		}
		b.WriteString(fmt.Sprintf("# Policy Verification: %s\n\n", res.PolicyPath))
		b.WriteString(fmt.Sprintf("- **Status:** %s\n", statusBadge))
		b.WriteString(fmt.Sprintf("- **Package:** `%s`\n", res.PackageName))
		b.WriteString(fmt.Sprintf("- **Total Diagnostics:** %d\n\n", len(res.Diagnostics)))

		if len(res.Diagnostics) == 0 {
			b.WriteString("No schema diagnostics detected. Policy is valid.\n")
		} else {
			b.WriteString("### Diagnostics\n\n")
			b.WriteString("| Severity | Line | Resource Type | Invalid Path | Message |\n")
			b.WriteString("| --- | --- | --- | --- | --- |\n")
			for _, d := range res.Diagnostics {
				b.WriteString(fmt.Sprintf("| %s | %d | `%s` | `%s` | %s |\n", d.Severity, d.Line, d.ResourceType, d.InvalidPath, d.Message))
			}
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported output format %q: expected %q, %q, or %q", format, FormatTable, FormatJSON, FormatMarkdown)
	}
}

// FormatEvalResult formats a single plan evaluation result across table, json, or markdown formats.
func FormatEvalResult(res *model.EvalResult, format string) (string, error) {
	if res == nil {
		return "", fmt.Errorf("eval result cannot be nil")
	}
	norm, err := normalizeFormat(format)
	if err != nil {
		return "", err
	}

	switch norm {
	case FormatJSON:
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling eval result to JSON: %w", err)
		}
		return string(data), nil

	case FormatTable:
		var b strings.Builder
		status := "PASSED"
		if !res.Passed {
			status = "BLOCKED"
		}
		b.WriteString(fmt.Sprintf("Repository:      %s\n", res.RepoName))
		b.WriteString(fmt.Sprintf("Snapshot ID:     %s\n", res.SnapshotID))
		b.WriteString(fmt.Sprintf("Total Resources: %d\n", res.TotalResources))
		b.WriteString(fmt.Sprintf("Status:          %s\n", status))
		b.WriteString(fmt.Sprintf("Violations:      %d\n", len(res.Violations)))

		if len(res.Violations) > 0 {
			b.WriteString("\n")
			w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RULE ID\tSEVERITY\tRESOURCE ADDRESS\tMESSAGE")
			for _, v := range res.Violations {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.RuleID, v.Severity, v.ResourceAddress, v.Message)
			}
			w.Flush()
		}
		return b.String(), nil

	case FormatMarkdown:
		var b strings.Builder
		statusBadge := "✅ PASSED"
		if !res.Passed {
			statusBadge = "❌ BLOCKED"
		}
		b.WriteString(fmt.Sprintf("# Evaluation Result: %s\n\n", res.RepoName))
		b.WriteString(fmt.Sprintf("- **Snapshot ID:** `%s`\n", res.SnapshotID))
		b.WriteString(fmt.Sprintf("- **Status:** %s\n", statusBadge))
		b.WriteString(fmt.Sprintf("- **Total Resources:** %d\n", res.TotalResources))
		b.WriteString(fmt.Sprintf("- **Total Violations:** %d\n\n", len(res.Violations)))

		if len(res.Violations) == 0 {
			b.WriteString("No policy violations found. Plan passed evaluation.\n")
		} else {
			b.WriteString("### Violations\n\n")
			b.WriteString("| Rule ID | Severity | Resource Address | Message | Remediation |\n")
			b.WriteString("| --- | --- | --- | --- | --- |\n")
			for _, v := range res.Violations {
				remDesc := "None"
				if v.Remediation != nil && v.Remediation.Description != "" {
					remDesc = v.Remediation.Description
				}
				b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s | %s |\n", v.RuleID, v.Severity, v.ResourceAddress, v.Message, remDesc))
			}
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported output format %q: expected %q, %q, or %q", format, FormatTable, FormatJSON, FormatMarkdown)
	}
}

// FormatBlastRadiusReport formats a cross-repo blast-radius backtest report across table, json, or markdown formats.
func FormatBlastRadiusReport(rep *model.BlastRadiusReport, format string) (string, error) {
	if rep == nil {
		return "", fmt.Errorf("blast radius report cannot be nil")
	}
	norm, err := normalizeFormat(format)
	if err != nil {
		return "", err
	}

	switch norm {
	case FormatJSON:
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling blast radius report to JSON: %w", err)
		}
		return string(data), nil

	case FormatTable:
		var b strings.Builder
		b.WriteString("============================================================\n")
		b.WriteString("               BLAST-RADIUS SIMULATION REPORT               \n")
		b.WriteString("============================================================\n")
		b.WriteString(fmt.Sprintf("Policy:             %s\n", rep.PolicyPath))
		b.WriteString(fmt.Sprintf("Repos Analyzed:     %d (Impacted: %d)\n", rep.TotalReposAnalyzed, rep.ImpactedReposCount))
		b.WriteString(fmt.Sprintf("Plans Analyzed:     %d (Blocked: %d)\n", rep.TotalPlansAnalyzed, rep.BlockedPlansCount))
		b.WriteString(fmt.Sprintf("Total Resources:    %d\n", rep.TotalResources))
		b.WriteString(fmt.Sprintf("Total Violations:   %d\n\n", rep.TotalViolations))

		// Deterministic provider breakdown
		providerKeys := make([]string, 0, len(rep.BreakdownByProvider))
		for k := range rep.BreakdownByProvider {
			providerKeys = append(providerKeys, k)
		}
		sort.Strings(providerKeys)

		b.WriteString("--- Breakdown by Cloud Provider ---\n")
		if len(providerKeys) == 0 {
			b.WriteString("No provider violations.\n\n")
		} else {
			w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROVIDER\tVIOLATIONS")
			for _, prov := range providerKeys {
				fmt.Fprintf(w, "%s\t%d\n", prov, rep.BreakdownByProvider[prov])
			}
			w.Flush()
			b.WriteString("\n")
		}

		b.WriteString("--- Repository Impact Summary ---\n")
		if len(rep.RepoImpacts) == 0 {
			b.WriteString("No repositories evaluated.\n")
		} else {
			w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "REPOSITORY\tPLANS TESTED\tBLOCKED PLANS\tVIOLATIONS\tSTATUS")
			for _, imp := range rep.RepoImpacts {
				status := "PASSED"
				if imp.BlockedPlansCount > 0 {
					status = "IMPACTED"
				}
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n",
					imp.RepoName, imp.TotalPlansTested, imp.BlockedPlansCount, len(imp.Violations), status)
			}
			w.Flush()
		}

		if rep.TotalViolations > 0 {
			b.WriteString("\n--- Detailed Violations by Repository ---\n")
			for _, imp := range rep.RepoImpacts {
				if len(imp.Violations) == 0 {
					continue
				}
				b.WriteString(fmt.Sprintf("\nRepository: %s (%d violations)\n", imp.RepoName, len(imp.Violations)))
				w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  RULE ID\tSEVERITY\tRESOURCE ADDRESS\tMESSAGE")
				for _, v := range imp.Violations {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", v.RuleID, v.Severity, v.ResourceAddress, v.Message)
				}
				w.Flush()
			}
		}

		return b.String(), nil

	case FormatMarkdown:
		var b strings.Builder
		b.WriteString("# Blast-Radius Simulation Report\n\n")
		b.WriteString(fmt.Sprintf("**Policy:** `%s`\n\n", rep.PolicyPath))

		b.WriteString("## Executive Summary\n\n")
		b.WriteString("| Metric | Value |\n")
		b.WriteString("| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Repositories Analyzed | %d |\n", rep.TotalReposAnalyzed))
		b.WriteString(fmt.Sprintf("| Impacted Repositories | %d |\n", rep.ImpactedReposCount))
		b.WriteString(fmt.Sprintf("| Total Plans Analyzed | %d |\n", rep.TotalPlansAnalyzed))
		b.WriteString(fmt.Sprintf("| Blocked Plans | %d |\n", rep.BlockedPlansCount))
		b.WriteString(fmt.Sprintf("| Total Resources Evaluated | %d |\n", rep.TotalResources))
		b.WriteString(fmt.Sprintf("| Total Policy Violations | %d |\n\n", rep.TotalViolations))

		// Deterministic provider breakdown
		providerKeys := make([]string, 0, len(rep.BreakdownByProvider))
		for k := range rep.BreakdownByProvider {
			providerKeys = append(providerKeys, k)
		}
		sort.Strings(providerKeys)

		b.WriteString("## Breakdown by Cloud Provider\n\n")
		if len(providerKeys) == 0 {
			b.WriteString("No provider violations detected.\n\n")
		} else {
			b.WriteString("| Cloud Provider | Violations |\n")
			b.WriteString("| --- | --- |\n")
			for _, prov := range providerKeys {
				b.WriteString(fmt.Sprintf("| `%s` | %d |\n", prov, rep.BreakdownByProvider[prov]))
			}
			b.WriteString("\n")
		}

		b.WriteString("## Repository Impact\n\n")
		if len(rep.RepoImpacts) == 0 {
			b.WriteString("No repositories evaluated.\n\n")
		} else {
			b.WriteString("| Repository | Plans Tested | Blocked Plans | Violations | Status |\n")
			b.WriteString("| --- | --- | --- | --- | --- |\n")
			for _, imp := range rep.RepoImpacts {
				statusBadge := "✅ PASSED"
				if imp.BlockedPlansCount > 0 {
					statusBadge = "❌ IMPACTED"
				}
				b.WriteString(fmt.Sprintf("| `%s` | %d | %d | %d | %s |\n",
					imp.RepoName, imp.TotalPlansTested, imp.BlockedPlansCount, len(imp.Violations), statusBadge))
			}
			b.WriteString("\n")
		}

		// Collapsible <details> blocks for each impacted repo
		hasImpacted := false
		for _, imp := range rep.RepoImpacts {
			if len(imp.Violations) > 0 {
				hasImpacted = true
				break
			}
		}

		if hasImpacted {
			b.WriteString("## Impact Details\n\n")
			for _, imp := range rep.RepoImpacts {
				if len(imp.Violations) == 0 {
					continue
				}
				b.WriteString(fmt.Sprintf("<details>\n<summary><b>%s</b> — %d violation(s)</summary>\n\n", imp.RepoName, len(imp.Violations)))
				b.WriteString("| Rule ID | Severity | Resource Address | Message |\n")
				b.WriteString("| --- | --- | --- | --- |\n")
				for _, v := range imp.Violations {
					b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n", v.RuleID, v.Severity, v.ResourceAddress, v.Message))
				}
				b.WriteString("\n</details>\n\n")
			}
		}

		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported output format %q: expected %q, %q, or %q", format, FormatTable, FormatJSON, FormatMarkdown)
	}
}

// FormatRemediationPatches formats a slice of remediation patches across table, json, or markdown formats.
func FormatRemediationPatches(patches []model.RemediationPatch, format string) (string, error) {
	norm, err := normalizeFormat(format)
	if err != nil {
		return "", err
	}

	if len(patches) == 0 {
		if norm == FormatJSON {
			return "[]", nil
		}
		return "No remediation patches generated.", nil
	}

	switch norm {
	case FormatJSON:
		data, err := json.MarshalIndent(patches, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling remediation patches to JSON: %w", err)
		}
		return string(data), nil

	case FormatTable:
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Remediation Patches: %d\n\n", len(patches)))
		w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "FILE\tRESOURCE ADDRESS\tDIFF LINES")
		for _, p := range patches {
			diffLines := 0
			trimmed := strings.TrimSpace(p.UnifiedDiff)
			if trimmed != "" {
				diffLines = len(strings.Split(trimmed, "\n"))
			}
			fmt.Fprintf(w, "%s\t%s\t%d\n", p.FilePath, p.ResourceAddress, diffLines)
		}
		w.Flush()
		return b.String(), nil

	case FormatMarkdown:
		var b strings.Builder
		b.WriteString(fmt.Sprintf("# Remediation Patches (%d)\n\n", len(patches)))
		for i, p := range patches {
			b.WriteString(fmt.Sprintf("### Patch %d: `%s`\n\n", i+1, p.ResourceAddress))
			b.WriteString(fmt.Sprintf("- **File:** `%s`\n\n", p.FilePath))
			b.WriteString("```diff\n")
			b.WriteString(p.UnifiedDiff)
			if !strings.HasSuffix(p.UnifiedDiff, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported output format %q: expected %q, %q, or %q", format, FormatTable, FormatJSON, FormatMarkdown)
	}
}
