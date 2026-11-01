package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/report"
)

// TestFormatVerificationResult tests table, JSON, and Markdown formatting for valid and invalid verification results.
func TestFormatVerificationResult(t *testing.T) {
	validRes := &model.VerificationResult{
		PolicyPath:  "policies/storage_encryption.rego",
		PackageName: "tfsim",
		Valid:       true,
		Diagnostics: []model.SchemaDiagnostic{},
	}

	invalidRes := &model.VerificationResult{
		PolicyPath:  "policies/broken_fail_open.rego",
		PackageName: "tfsim",
		Valid:       false,
		Diagnostics: []model.SchemaDiagnostic{
			{
				PolicyFile:   "policies/broken_fail_open.rego",
				Line:         15,
				ResourceType: "azurerm_storage_account",
				InvalidPath:  "https_only_enabled",
				Message:      "attribute https_only_enabled does not exist in schema for azurerm_storage_account",
				Severity:     "ERROR",
			},
			{
				PolicyFile:   "policies/broken_fail_open.rego",
				Line:         25,
				ResourceType: "aws_s3_bucket",
				InvalidPath:  "encrypt",
				Message:      "attribute encrypt does not exist in schema for aws_s3_bucket",
				Severity:     "WARNING",
			},
		},
	}

	// 1. Table format tests
	t.Run("Table_Valid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(validRes, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "VALID") && !strings.Contains(out, "PASSED") {
			t.Errorf("expected output to contain VALID or PASSED, got:\n%s", out)
		}
		if !strings.Contains(out, "policies/storage_encryption.rego") {
			t.Errorf("expected output to contain policy path, got:\n%s", out)
		}
	})

	t.Run("Table_Invalid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(invalidRes, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "INVALID") && !strings.Contains(out, "FAILED") {
			t.Errorf("expected output to contain INVALID, got:\n%s", out)
		}
		if !strings.Contains(out, "15") || !strings.Contains(out, "https_only_enabled") {
			t.Errorf("expected output to contain diagnostic details, got:\n%s", out)
		}
		if !strings.Contains(out, "azurerm_storage_account") {
			t.Errorf("expected output to contain resource type, got:\n%s", out)
		}
	})

	// 2. JSON format tests
	t.Run("JSON_Valid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(validRes, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.VerificationResult
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON output: %v\nOutput: %s", err, out)
		}
		if !parsed.Valid {
			t.Errorf("expected parsed.Valid == true, got false")
		}
		if parsed.PolicyPath != validRes.PolicyPath {
			t.Errorf("expected PolicyPath %q, got %q", validRes.PolicyPath, parsed.PolicyPath)
		}
	})

	t.Run("JSON_Invalid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(invalidRes, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.VerificationResult
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON output: %v\nOutput: %s", err, out)
		}
		if parsed.Valid {
			t.Errorf("expected parsed.Valid == false, got true")
		}
		if len(parsed.Diagnostics) != 2 {
			t.Errorf("expected 2 diagnostics, got %d", len(parsed.Diagnostics))
		}
	})

	// 3. Markdown format tests
	t.Run("Markdown_Valid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(validRes, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "VALID") && !strings.Contains(out, "PASSED") {
			t.Errorf("expected markdown to indicate valid status, got:\n%s", out)
		}
	})

	t.Run("Markdown_Invalid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(invalidRes, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "INVALID") && !strings.Contains(out, "FAILED") {
			t.Errorf("expected markdown to indicate invalid status, got:\n%s", out)
		}
		if !strings.Contains(out, "|") || !strings.Contains(out, "https_only_enabled") {
			t.Errorf("expected markdown table with diagnostic details, got:\n%s", out)
		}
	})
}

// TestFormatEvalResult tests table, JSON, and Markdown formatting for passing and blocked evaluation results.
func TestFormatEvalResult(t *testing.T) {
	passRes := &model.EvalResult{
		SnapshotID:     "snap-prod-101",
		RepoName:       "repo-payments",
		TotalResources: 5,
		Passed:         true,
		Violations:     []model.PolicyViolation{},
	}

	blockedRes := &model.EvalResult{
		SnapshotID:     "snap-staging-202",
		RepoName:       "repo-data",
		TotalResources: 8,
		Passed:         false,
		Violations: []model.PolicyViolation{
			{
				RuleID:          "AWS-S3-ENCRYPT-001",
				Severity:        "HIGH",
				Message:         "S3 bucket must have server-side encryption enabled",
				ResourceAddress: "aws_s3_bucket.unencrypted_reports",
				ResourceType:    "aws_s3_bucket",
				ResourceName:    "unencrypted_reports",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{"server_side_encryption_configuration", "rule", "sse_algorithm"},
					SuggestedVal:  "aws:kms",
					Description:   "Enable KMS encryption",
				},
			},
			{
				RuleID:          "AZURE-STORAGE-HTTPS-001",
				Severity:        "CRITICAL",
				Message:         "Storage account must enforce HTTPS traffic only",
				ResourceAddress: "azurerm_storage_account.insecure_transfer",
				ResourceType:    "azurerm_storage_account",
				ResourceName:    "insecure_transfer",
			},
		},
	}

	// 1. Table format tests
	t.Run("Table_Passed", func(t *testing.T) {
		out, err := report.FormatEvalResult(passRes, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "PASSED") {
			t.Errorf("expected table output to contain PASSED, got:\n%s", out)
		}
		if !strings.Contains(out, "repo-payments") {
			t.Errorf("expected table output to contain repo name, got:\n%s", out)
		}
	})

	t.Run("Table_Blocked", func(t *testing.T) {
		out, err := report.FormatEvalResult(blockedRes, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "BLOCKED") {
			t.Errorf("expected table output to contain BLOCKED, got:\n%s", out)
		}
		if !strings.Contains(out, "AWS-S3-ENCRYPT-001") || !strings.Contains(out, "AZURE-STORAGE-HTTPS-001") {
			t.Errorf("expected table output to contain rule IDs, got:\n%s", out)
		}
		if !strings.Contains(out, "aws_s3_bucket.unencrypted_reports") {
			t.Errorf("expected table output to contain resource address, got:\n%s", out)
		}
	})

	// 2. JSON format tests
	t.Run("JSON_Passed", func(t *testing.T) {
		out, err := report.FormatEvalResult(passRes, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.EvalResult
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
		}
		if !parsed.Passed {
			t.Errorf("expected Passed == true, got false")
		}
		if parsed.RepoName != "repo-payments" {
			t.Errorf("expected RepoName repo-payments, got %s", parsed.RepoName)
		}
	})

	t.Run("JSON_Blocked", func(t *testing.T) {
		out, err := report.FormatEvalResult(blockedRes, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.EvalResult
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
		}
		if parsed.Passed {
			t.Errorf("expected Passed == false, got true")
		}
		if len(parsed.Violations) != 2 {
			t.Errorf("expected 2 violations, got %d", len(parsed.Violations))
		}
	})

	// 3. Markdown format tests
	t.Run("Markdown_Passed", func(t *testing.T) {
		out, err := report.FormatEvalResult(passRes, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "PASSED") {
			t.Errorf("expected markdown to indicate PASSED, got:\n%s", out)
		}
	})

	t.Run("Markdown_Blocked", func(t *testing.T) {
		out, err := report.FormatEvalResult(blockedRes, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "BLOCKED") {
			t.Errorf("expected markdown to indicate BLOCKED, got:\n%s", out)
		}
		if !strings.Contains(out, "|") || !strings.Contains(out, "AWS-S3-ENCRYPT-001") {
			t.Errorf("expected markdown table with violation rows, got:\n%s", out)
		}
		if !strings.Contains(out, "Enable KMS encryption") {
			t.Errorf("expected markdown to include remediation description, got:\n%s", out)
		}
	})
}

// TestFormatBlastRadiusReport tests table, JSON, and Markdown formatting for multi-repo and clean blast-radius reports.
func TestFormatBlastRadiusReport(t *testing.T) {
	multiRep := &model.BlastRadiusReport{
		PolicyPath:          "policies/storage_encryption.rego",
		TotalReposAnalyzed:  3,
		ImpactedReposCount:  2,
		TotalPlansAnalyzed:  5,
		BlockedPlansCount:   3,
		TotalResources:      20,
		TotalViolations:     3,
		BreakdownByProvider: map[string]int{"aws": 1, "azurerm": 1, "google": 1},
		RepoImpacts: []model.RepoImpact{
			{
				RepoName:          "repo-data-azure",
				TotalPlansTested:  2,
				BlockedPlansCount: 1,
				Violations: []model.PolicyViolation{
					{
						RuleID:          "AZURE-STORAGE-HTTPS-001",
						Severity:        "HIGH",
						Message:         "Storage account must enforce HTTPS traffic only",
						ResourceAddress: "azurerm_storage_account.insecure_transfer",
						ResourceType:    "azurerm_storage_account",
						ResourceName:    "insecure_transfer",
					},
				},
			},
			{
				RepoName:          "repo-payments-aws",
				TotalPlansTested:  3,
				BlockedPlansCount: 2,
				Violations: []model.PolicyViolation{
					{
						RuleID:          "AWS-S3-ENCRYPT-001",
						Severity:        "HIGH",
						Message:         "S3 bucket must have server-side encryption enabled",
						ResourceAddress: "aws_s3_bucket.unencrypted_reports",
						ResourceType:    "aws_s3_bucket",
						ResourceName:    "unencrypted_reports",
					},
				},
			},
		},
	}

	cleanRep := &model.BlastRadiusReport{
		PolicyPath:          "policies/clean_policy.rego",
		TotalReposAnalyzed:  1,
		ImpactedReposCount:  0,
		TotalPlansAnalyzed:  2,
		BlockedPlansCount:   0,
		TotalResources:      10,
		TotalViolations:     0,
		BreakdownByProvider: map[string]int{},
		RepoImpacts: []model.RepoImpact{
			{
				RepoName:          "repo-clean-aws",
				TotalPlansTested:  2,
				BlockedPlansCount: 0,
				Violations:        []model.PolicyViolation{},
			},
		},
	}

	// 1. Table format tests
	t.Run("Table_MultiRepo", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(multiRep, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "storage_encryption.rego") {
			t.Errorf("expected table to contain policy path, got:\n%s", out)
		}
		if !strings.Contains(out, "repo-data-azure") || !strings.Contains(out, "repo-payments-aws") {
			t.Errorf("expected table to list impacted repos, got:\n%s", out)
		}
		if !strings.Contains(out, "aws") || !strings.Contains(out, "azurerm") {
			t.Errorf("expected table to display provider breakdown, got:\n%s", out)
		}
	})

	t.Run("Table_Clean", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(cleanRep, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "clean_policy.rego") {
			t.Errorf("expected table to contain policy path, got:\n%s", out)
		}
	})

	// 2. JSON format tests
	t.Run("JSON_MultiRepo", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(multiRep, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.BlastRadiusReport
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
		}
		if parsed.TotalReposAnalyzed != 3 {
			t.Errorf("expected TotalReposAnalyzed=3, got %d", parsed.TotalReposAnalyzed)
		}
		if parsed.ImpactedReposCount != 2 {
			t.Errorf("expected ImpactedReposCount=2, got %d", parsed.ImpactedReposCount)
		}
		if parsed.BreakdownByProvider["aws"] != 1 {
			t.Errorf("expected aws provider count=1, got %d", parsed.BreakdownByProvider["aws"])
		}
		if len(parsed.RepoImpacts) != 2 {
			t.Errorf("expected 2 RepoImpacts, got %d", len(parsed.RepoImpacts))
		}
	})

	t.Run("JSON_Clean", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(cleanRep, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed model.BlastRadiusReport
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
		}
		if parsed.ImpactedReposCount != 0 {
			t.Errorf("expected ImpactedReposCount=0, got %d", parsed.ImpactedReposCount)
		}
		if parsed.TotalViolations != 0 {
			t.Errorf("expected TotalViolations=0, got %d", parsed.TotalViolations)
		}
	})

	// 3. Markdown format tests
	t.Run("Markdown_MultiRepo", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(multiRep, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "storage_encryption.rego") {
			t.Errorf("expected markdown to contain policy path, got:\n%s", out)
		}
		if !strings.Contains(out, "|") {
			t.Errorf("expected markdown tables, got:\n%s", out)
		}
		// Collapsible details block for impacted repos
		if !strings.Contains(out, "<details>") || !strings.Contains(out, "</details>") {
			t.Errorf("expected markdown to contain <details> collapsible blocks, got:\n%s", out)
		}
		if !strings.Contains(out, "repo-data-azure") || !strings.Contains(out, "repo-payments-aws") {
			t.Errorf("expected markdown to contain repo names, got:\n%s", out)
		}
	})

	t.Run("Markdown_Clean", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(cleanRep, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "clean_policy.rego") {
			t.Errorf("expected markdown to contain clean policy path, got:\n%s", out)
		}
	})
}

// TestFormatRemediationPatches tests formatting for single, multiple, empty, and nil remediation patches.
func TestFormatRemediationPatches(t *testing.T) {
	patch1 := model.RemediationPatch{
		FilePath:        "infra/main.tf",
		ResourceAddress: "aws_s3_bucket.unencrypted_reports",
		OriginalHCL:     "resource \"aws_s3_bucket\" \"unencrypted_reports\" {\n  bucket = \"my-bucket\"\n}\n",
		PatchedHCL:      "resource \"aws_s3_bucket\" \"unencrypted_reports\" {\n  bucket = \"my-bucket\"\n  server_side_encryption_configuration {\n  }\n}\n",
		UnifiedDiff:     "--- a/infra/main.tf\n+++ b/infra/main.tf\n@@ -1,3 +1,5 @@\n resource \"aws_s3_bucket\" \"unencrypted_reports\" {\n   bucket = \"my-bucket\"\n+  server_side_encryption_configuration {\n+  }\n }\n",
	}

	patch2 := model.RemediationPatch{
		FilePath:        "modules/storage/main.tf",
		ResourceAddress: "azurerm_storage_account.insecure_transfer",
		OriginalHCL:     "resource \"azurerm_storage_account\" \"insecure_transfer\" {\n  https_traffic_only_enabled = false\n}\n",
		PatchedHCL:      "resource \"azurerm_storage_account\" \"insecure_transfer\" {\n  https_traffic_only_enabled = true\n}\n",
		UnifiedDiff:     "--- a/modules/storage/main.tf\n+++ b/modules/storage/main.tf\n@@ -1,3 +1,3 @@\n resource \"azurerm_storage_account\" \"insecure_transfer\" {\n-  https_traffic_only_enabled = false\n+  https_traffic_only_enabled = true\n }\n",
	}

	// 1. Table format
	t.Run("Table_SingleAndMultiple", func(t *testing.T) {
		outSingle, err := report.FormatRemediationPatches([]model.RemediationPatch{patch1}, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(outSingle, "infra/main.tf") || !strings.Contains(outSingle, "aws_s3_bucket.unencrypted_reports") {
			t.Errorf("expected table to show file and address, got:\n%s", outSingle)
		}

		outMulti, err := report.FormatRemediationPatches([]model.RemediationPatch{patch1, patch2}, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(outMulti, "infra/main.tf") || !strings.Contains(outMulti, "modules/storage/main.tf") {
			t.Errorf("expected table to show both files, got:\n%s", outMulti)
		}
	})

	t.Run("Table_EmptyAndNil", func(t *testing.T) {
		outNil, err := report.FormatRemediationPatches(nil, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error for nil: %v", err)
		}
		if !strings.Contains(outNil, "No remediation patches generated.") {
			t.Errorf("expected 'No remediation patches generated.' for nil, got:\n%s", outNil)
		}

		outEmpty, err := report.FormatRemediationPatches([]model.RemediationPatch{}, report.FormatTable)
		if err != nil {
			t.Fatalf("unexpected error for empty slice: %v", err)
		}
		if !strings.Contains(outEmpty, "No remediation patches generated.") {
			t.Errorf("expected 'No remediation patches generated.' for empty slice, got:\n%s", outEmpty)
		}
	})

	// 2. JSON format
	t.Run("JSON_Patches", func(t *testing.T) {
		out, err := report.FormatRemediationPatches([]model.RemediationPatch{patch1, patch2}, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed []model.RemediationPatch
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v\nOutput: %s", err, out)
		}
		if len(parsed) != 2 {
			t.Errorf("expected 2 patches in JSON, got %d", len(parsed))
		}
	})

	t.Run("JSON_EmptyAndNil", func(t *testing.T) {
		outNil, err := report.FormatRemediationPatches(nil, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error for nil: %v", err)
		}
		if strings.TrimSpace(outNil) != "[]" {
			t.Errorf("expected '[]' for nil JSON patches, got %q", outNil)
		}

		outEmpty, err := report.FormatRemediationPatches([]model.RemediationPatch{}, report.FormatJSON)
		if err != nil {
			t.Fatalf("unexpected error for empty slice: %v", err)
		}
		if strings.TrimSpace(outEmpty) != "[]" {
			t.Errorf("expected '[]' for empty JSON patches, got %q", outEmpty)
		}
	})

	// 3. Markdown format
	t.Run("Markdown_DiffFencedCode", func(t *testing.T) {
		out, err := report.FormatRemediationPatches([]model.RemediationPatch{patch1}, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "```diff") {
			t.Errorf("expected markdown to contain ```diff fenced code block, got:\n%s", out)
		}
		if !strings.Contains(out, "+  server_side_encryption_configuration {") {
			t.Errorf("expected markdown to contain diff content, got:\n%s", out)
		}
	})

	t.Run("Markdown_EmptyAndNil", func(t *testing.T) {
		outNil, err := report.FormatRemediationPatches(nil, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error for nil: %v", err)
		}
		if !strings.Contains(outNil, "No remediation patches generated.") {
			t.Errorf("expected 'No remediation patches generated.' for nil, got:\n%s", outNil)
		}

		outEmpty, err := report.FormatRemediationPatches([]model.RemediationPatch{}, report.FormatMarkdown)
		if err != nil {
			t.Fatalf("unexpected error for empty: %v", err)
		}
		if !strings.Contains(outEmpty, "No remediation patches generated.") {
			t.Errorf("expected 'No remediation patches generated.' for empty, got:\n%s", outEmpty)
		}
	})
}

// TestFormatter_UnsupportedFormat validates error handling when an unsupported format string is provided.
func TestFormatter_UnsupportedFormat(t *testing.T) {
	vRes := &model.VerificationResult{}
	eRes := &model.EvalResult{}
	bRep := &model.BlastRadiusReport{}
	patches := []model.RemediationPatch{}

	unsupportedFormats := []string{"yaml", "xml", "csv", "invalid"}

	for _, f := range unsupportedFormats {
		t.Run("FormatVerificationResult_"+f, func(t *testing.T) {
			_, err := report.FormatVerificationResult(vRes, f)
			if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
				t.Errorf("expected unsupported output format error for %q, got: %v", f, err)
			}
		})

		t.Run("FormatEvalResult_"+f, func(t *testing.T) {
			_, err := report.FormatEvalResult(eRes, f)
			if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
				t.Errorf("expected unsupported output format error for %q, got: %v", f, err)
			}
		})

		t.Run("FormatBlastRadiusReport_"+f, func(t *testing.T) {
			_, err := report.FormatBlastRadiusReport(bRep, f)
			if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
				t.Errorf("expected unsupported output format error for %q, got: %v", f, err)
			}
		})

		t.Run("FormatRemediationPatches_"+f, func(t *testing.T) {
			_, err := report.FormatRemediationPatches(patches, f)
			if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
				t.Errorf("expected unsupported output format error for %q, got: %v", f, err)
			}
		})
	}
}

// TestFormatter_NilInputs validates error handling when nil model pointers are passed.
func TestFormatter_NilInputs(t *testing.T) {
	t.Run("Nil_VerificationResult", func(t *testing.T) {
		_, err := report.FormatVerificationResult(nil, report.FormatJSON)
		if err == nil {
			t.Error("expected error for nil VerificationResult, got nil")
		}
	})

	t.Run("Nil_EvalResult", func(t *testing.T) {
		_, err := report.FormatEvalResult(nil, report.FormatTable)
		if err == nil {
			t.Error("expected error for nil EvalResult, got nil")
		}
	})

	t.Run("Nil_BlastRadiusReport", func(t *testing.T) {
		_, err := report.FormatBlastRadiusReport(nil, report.FormatMarkdown)
		if err == nil {
			t.Error("expected error for nil BlastRadiusReport, got nil")
		}
	})
}

type testSARIFLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID               string `json:"id"`
					ShortDescription *struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation *struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region *struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
				LogicalLocations []struct {
					Name               string `json:"name"`
					FullyQualifiedName string `json:"fullyQualifiedName"`
					Kind               string `json:"kind"`
				} `json:"logicalLocations"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// TestFormatVerificationResult_SARIF tests SARIF v2.1.0 formatting for valid and invalid verification results.
func TestFormatVerificationResult_SARIF(t *testing.T) {
	validRes := &model.VerificationResult{
		PolicyPath:  `policies\storage_encryption.rego`,
		PackageName: "tfsim",
		Valid:       true,
		Diagnostics: []model.SchemaDiagnostic{},
	}

	invalidRes := &model.VerificationResult{
		PolicyPath:  `policies\broken_fail_open.rego`,
		PackageName: "tfsim",
		Valid:       false,
		Diagnostics: []model.SchemaDiagnostic{
			{
				PolicyFile:   `policies\broken_fail_open.rego`,
				Line:         15,
				ResourceType: "azurerm_storage_account",
				InvalidPath:  "https_only_enabled",
				Message:      "attribute https_only_enabled does not exist in schema for azurerm_storage_account",
				Severity:     "ERROR",
			},
			{
				PolicyFile:   `policies\broken_fail_open.rego`,
				Line:         25,
				ResourceType: "aws_s3_bucket",
				InvalidPath:  "encrypt",
				Message:      "attribute encrypt does not exist in schema for aws_s3_bucket",
				Severity:     "WARNING",
			},
			{
				PolicyFile:   `policies\broken_fail_open.rego`,
				Line:         1,
				ResourceType: "fixture:fail",
				InvalidPath:  "testdata/plans/repo_data_azure.json",
				Message:      `Fail fixture "testdata/plans/repo_data_azure.json" passed unexpectedly: expected at least 1 violation, got 0 — potential silent fail-open bug`,
				Severity:     "ERROR",
			},
		},
	}

	t.Run("SARIF_Valid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(validRes, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, `"results": []`) || !strings.Contains(out, `"rules": []`) {
			t.Errorf("expected raw SARIF JSON to contain non-null empty arrays, got:\n%s", out)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF JSON: %v\nOutput:\n%s", err, out)
		}
		if sarif.Version != "2.1.0" {
			t.Errorf("expected version 2.1.0, got %q", sarif.Version)
		}
		if sarif.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
			t.Errorf("expected $schema https://json.schemastore.org/sarif-2.1.0.json, got %q", sarif.Schema)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
		}
		if sarif.Runs[0].Tool.Driver.Name != "tf-sim" {
			t.Errorf("expected driver.name tf-sim, got %q", sarif.Runs[0].Tool.Driver.Name)
		}
		if len(sarif.Runs[0].Results) != 0 {
			t.Errorf("expected 0 results for valid verification, got %d", len(sarif.Runs[0].Results))
		}
	})

	t.Run("SARIF_Invalid", func(t *testing.T) {
		out, err := report.FormatVerificationResult(invalidRes, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF JSON: %v\nOutput:\n%s", err, out)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
		}
		run := sarif.Runs[0]
		if len(run.Results) != 3 {
			t.Fatalf("expected 3 results, got %d", len(run.Results))
		}
		if len(run.Tool.Driver.Rules) != 2 {
			t.Fatalf("expected 2 deduplicated rules (TFSIM-VERIFY-SCHEMA and TFSIM-VERIFY-FIXTURE), got %d", len(run.Tool.Driver.Rules))
		}

		if run.Results[0].RuleID != "TFSIM-VERIFY-SCHEMA" || run.Results[0].Level != "error" {
			t.Errorf("unexpected result[0] ruleId=%q level=%q", run.Results[0].RuleID, run.Results[0].Level)
		}
		if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "policies/broken_fail_open.rego" {
			t.Errorf("expected forward-slash URI 'policies/broken_fail_open.rego', got %q", run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 15 {
			t.Errorf("expected startLine 15, got %d", run.Results[0].Locations[0].PhysicalLocation.Region.StartLine)
		}
		if len(run.Results[0].Locations[0].LogicalLocations) != 1 || run.Results[0].Locations[0].LogicalLocations[0].FullyQualifiedName != "azurerm_storage_account.https_only_enabled" {
			t.Errorf("unexpected logicalLocations for result[0]: %+v", run.Results[0].Locations[0].LogicalLocations)
		}

		if run.Results[1].RuleID != "TFSIM-VERIFY-SCHEMA" || run.Results[1].Level != "warning" {
			t.Errorf("unexpected result[1] ruleId=%q level=%q", run.Results[1].RuleID, run.Results[1].Level)
		}
		if run.Results[1].Locations[0].PhysicalLocation.Region.StartLine != 25 {
			t.Errorf("expected startLine 25, got %d", run.Results[1].Locations[0].PhysicalLocation.Region.StartLine)
		}

		if run.Results[2].RuleID != "TFSIM-VERIFY-FIXTURE" || run.Results[2].Level != "error" {
			t.Errorf("unexpected result[2] ruleId=%q level=%q", run.Results[2].RuleID, run.Results[2].Level)
		}
		if run.Results[2].Locations[0].PhysicalLocation.Region.StartLine != 1 {
			t.Errorf("expected startLine 1, got %d", run.Results[2].Locations[0].PhysicalLocation.Region.StartLine)
		}
	})
}

// TestFormatEvalResult_SARIF tests SARIF v2.1.0 formatting for passing and blocked evaluation results.
func TestFormatEvalResult_SARIF(t *testing.T) {
	passRes := &model.EvalResult{
		SnapshotID:     "snap-prod-101",
		RepoName:       "repo-payments",
		TotalResources: 5,
		Passed:         true,
		Violations:     []model.PolicyViolation{},
	}

	blockedRes := &model.EvalResult{
		SnapshotID:     "snap-staging-202",
		RepoName:       `repos\repo-data`,
		TotalResources: 8,
		Passed:         false,
		Violations: []model.PolicyViolation{
			{
				RuleID:          "AWS-S3-ENCRYPT-001",
				Severity:        "HIGH",
				Message:         "S3 bucket must have server-side encryption enabled",
				ResourceAddress: "aws_s3_bucket.unencrypted_reports",
				ResourceType:    "aws_s3_bucket",
				ResourceName:    "unencrypted_reports",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{"server_side_encryption_configuration", "rule", "sse_algorithm"},
					SuggestedVal:  "aws:kms",
					Description:   "Enable KMS encryption",
				},
			},
			{
				RuleID:          "AZURE-STORAGE-HTTPS-001",
				Severity:        "CRITICAL",
				Message:         "Storage account must enforce HTTPS traffic only",
				ResourceAddress: "azurerm_storage_account.insecure_transfer",
				ResourceType:    "azurerm_storage_account",
				ResourceName:    "insecure_transfer",
			},
			{
				RuleID:          "GCP-STORAGE-UBLA-001",
				Severity:        "MEDIUM",
				Message:         "Bucket must enable uniform bucket-level access",
				ResourceAddress: "google_storage_bucket.analytics_archive",
				ResourceType:    "google_storage_bucket",
				ResourceName:    "analytics_archive",
			},
			{
				RuleID:          "AWS-S3-ENCRYPT-001",
				Severity:        "LOW",
				Message:         "Secondary S3 bucket missing encryption",
				ResourceAddress: "aws_s3_bucket.secondary",
				ResourceType:    "aws_s3_bucket",
				ResourceName:    "secondary",
			},
		},
	}

	t.Run("SARIF_Passed", func(t *testing.T) {
		out, err := report.FormatEvalResult(passRes, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, `"results": []`) || !strings.Contains(out, `"rules": []`) {
			t.Errorf("expected empty results and rules arrays in SARIF output, got:\n%s", out)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF: %v", err)
		}
		if len(sarif.Runs[0].Results) != 0 || len(sarif.Runs[0].Tool.Driver.Rules) != 0 {
			t.Errorf("expected 0 results and 0 rules, got %d results and %d rules", len(sarif.Runs[0].Results), len(sarif.Runs[0].Tool.Driver.Rules))
		}
	})

	t.Run("SARIF_Blocked", func(t *testing.T) {
		out, err := report.FormatEvalResult(blockedRes, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF: %v", err)
		}
		run := sarif.Runs[0]
		if len(run.Results) != 4 {
			t.Fatalf("expected 4 results, got %d", len(run.Results))
		}
		// 4 violations but only 3 distinct RuleIDs
		if len(run.Tool.Driver.Rules) != 3 {
			t.Errorf("expected 3 deduplicated rules, got %d", len(run.Tool.Driver.Rules))
		}

		expectedLevels := []string{"error", "error", "warning", "note"}
		for i, wantLevel := range expectedLevels {
			if run.Results[i].Level != wantLevel {
				t.Errorf("result[%d] expected level %q, got %q", i, wantLevel, run.Results[i].Level)
			}
			if run.Results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI != "repos/repo-data" {
				t.Errorf("result[%d] expected URI 'repos/repo-data', got %q", i, run.Results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
			if run.Results[i].Locations[0].LogicalLocations[0].FullyQualifiedName != blockedRes.Violations[i].ResourceAddress {
				t.Errorf("result[%d] expected FQN %q, got %q", i, blockedRes.Violations[i].ResourceAddress, run.Results[i].Locations[0].LogicalLocations[0].FullyQualifiedName)
			}
		}

		if !strings.Contains(run.Results[0].Message.Text, "(Remediation: Enable KMS encryption)") {
			t.Errorf("expected result[0] message to include remediation description, got %q", run.Results[0].Message.Text)
		}
	})
}

// TestFormatBlastRadiusReport_SARIF tests SARIF v2.1.0 formatting for multi-repo and clean blast-radius reports.
func TestFormatBlastRadiusReport_SARIF(t *testing.T) {
	multiRep := &model.BlastRadiusReport{
		PolicyPath:         "policies/storage_encryption.rego",
		TotalReposAnalyzed: 2,
		ImpactedReposCount: 2,
		TotalPlansAnalyzed: 2,
		BlockedPlansCount:  2,
		TotalResources:     10,
		TotalViolations:    3,
		RepoImpacts: []model.RepoImpact{
			{
				RepoName:          "repo-data-azure",
				TotalPlansTested:  1,
				BlockedPlansCount: 1,
				Violations: []model.PolicyViolation{
					{
						RuleID:          "AZURE-STORAGE-HTTPS-001",
						Severity:        "HIGH",
						Message:         "Storage account must enforce HTTPS traffic only",
						ResourceAddress: "azurerm_storage_account.insecure_transfer",
						ResourceType:    "azurerm_storage_account",
						ResourceName:    "insecure_transfer",
					},
				},
			},
			{
				RepoName:          "repo-payments-aws",
				TotalPlansTested:  1,
				BlockedPlansCount: 1,
				Violations: []model.PolicyViolation{
					{
						RuleID:          "AWS-S3-ENCRYPT-001",
						Severity:        "HIGH",
						Message:         "S3 bucket must have server-side encryption enabled",
						ResourceAddress: "aws_s3_bucket.unencrypted_reports",
						ResourceType:    "aws_s3_bucket",
						ResourceName:    "unencrypted_reports",
					},
					{
						RuleID:          "AWS-S3-ENCRYPT-001",
						Severity:        "MEDIUM",
						Message:         "S3 bucket logs must have encryption enabled",
						ResourceAddress: "aws_s3_bucket.unencrypted_logs",
						ResourceType:    "aws_s3_bucket",
						ResourceName:    "unencrypted_logs",
					},
				},
			},
		},
	}

	cleanRep := &model.BlastRadiusReport{
		PolicyPath:         "policies/clean_policy.rego",
		TotalReposAnalyzed: 1,
		ImpactedReposCount: 0,
		TotalPlansAnalyzed: 1,
		BlockedPlansCount:  0,
		TotalResources:     5,
		TotalViolations:    0,
		RepoImpacts: []model.RepoImpact{
			{
				RepoName:          "repo-clean-aws",
				TotalPlansTested:  1,
				BlockedPlansCount: 0,
				Violations:        []model.PolicyViolation{},
			},
		},
	}

	t.Run("SARIF_MultiRepo", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(multiRep, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF: %v", err)
		}
		run := sarif.Runs[0]
		if len(run.Results) != 3 {
			t.Fatalf("expected 3 results across repos, got %d", len(run.Results))
		}
		if run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "repo-data-azure" {
			t.Errorf("expected result[0] URI 'repo-data-azure', got %q", run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		if run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != "repo-payments-aws" {
			t.Errorf("expected result[1] URI 'repo-payments-aws', got %q", run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		if run.Results[2].Locations[0].PhysicalLocation.ArtifactLocation.URI != "repo-payments-aws" {
			t.Errorf("expected result[2] URI 'repo-payments-aws', got %q", run.Results[2].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	})

	t.Run("SARIF_Clean", func(t *testing.T) {
		out, err := report.FormatBlastRadiusReport(cleanRep, report.FormatSARIF)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, `"results": []`) {
			t.Errorf("expected clean report SARIF to contain '\"results\": []', got:\n%s", out)
		}

		var sarif testSARIFLog
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Fatalf("failed to unmarshal SARIF: %v", err)
		}
		if len(sarif.Runs[0].Results) != 0 {
			t.Errorf("expected 0 results for clean blast radius report, got %d", len(sarif.Runs[0].Results))
		}
	})
}

// TestFormatRemediationPatches_SARIF tests SARIF v2.1.0 formatting for non-empty remediation patches.
func TestFormatRemediationPatches_SARIF(t *testing.T) {
	patch := model.RemediationPatch{
		FilePath:        `modules\storage\main.tf`,
		ResourceAddress: "azurerm_storage_account.insecure_transfer",
		OriginalHCL:     "resource \"azurerm_storage_account\" \"insecure_transfer\" {\n  https_traffic_only_enabled = false\n}\n",
		PatchedHCL:      "resource \"azurerm_storage_account\" \"insecure_transfer\" {\n  https_traffic_only_enabled = true\n}\n",
		UnifiedDiff:     "--- a/modules/storage/main.tf\n+++ b/modules/storage/main.tf\n@@ -1,3 +1,3 @@\n resource \"azurerm_storage_account\" \"insecure_transfer\" {\n-  https_traffic_only_enabled = false\n+  https_traffic_only_enabled = true\n }\n",
	}

	out, err := report.FormatRemediationPatches([]model.RemediationPatch{patch}, report.FormatSARIF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif testSARIFLog
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v\nOutput:\n%s", err, out)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	res := run.Results[0]
	if res.RuleID != "TFSIM-REMEDIATE" {
		t.Errorf("expected ruleId 'TFSIM-REMEDIATE', got %q", res.RuleID)
	}
	if res.Level != "note" {
		t.Errorf("expected level 'note', got %q", res.Level)
	}
	if res.Message.Text != patch.UnifiedDiff {
		t.Errorf("expected message.text to match UnifiedDiff, got %q", res.Message.Text)
	}
	if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "modules/storage/main.tf" {
		t.Errorf("expected normalized forward-slash URI 'modules/storage/main.tf', got %q", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if len(res.Locations[0].LogicalLocations) != 1 || res.Locations[0].LogicalLocations[0].FullyQualifiedName != patch.ResourceAddress {
		t.Errorf("expected logicalLocation FQN %q, got %+v", patch.ResourceAddress, res.Locations[0].LogicalLocations)
	}
}

// TestFormatRemediationPatches_SARIF_EmptyAndNil tests SARIF v2.1.0 formatting when remediation patches are nil or empty.
func TestFormatRemediationPatches_SARIF_EmptyAndNil(t *testing.T) {
	for _, tc := range []struct {
		name    string
		patches []model.RemediationPatch
		format  string
	}{
		{name: "NilSlice_LowercaseSARIF", patches: nil, format: "sarif"},
		{name: "EmptySlice_UppercaseSARIF", patches: []model.RemediationPatch{}, format: "SARIF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := report.FormatRemediationPatches(tc.patches, tc.format)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(out, `"results": []`) || !strings.Contains(out, `"rules": []`) {
				t.Errorf("expected SARIF output to contain '\"results\": []' and '\"rules\": []', got:\n%s", out)
			}

			var sarif testSARIFLog
			if err := json.Unmarshal([]byte(out), &sarif); err != nil {
				t.Fatalf("failed to unmarshal SARIF JSON: %v\nOutput:\n%s", err, out)
			}
			if sarif.Version != "2.1.0" {
				t.Errorf("expected version 2.1.0, got %q", sarif.Version)
			}
			if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 0 {
				t.Errorf("expected 1 run with 0 results, got %+v", sarif.Runs)
			}
		})
	}
}
