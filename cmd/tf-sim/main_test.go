package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
)

const compliantPlanJSON = `{
  "format_version": "1.2",
  "terraform_version": "1.8.0",
  "resource_changes": [
    {
      "address": "azurerm_storage_account.compliant_lake",
      "mode": "managed",
      "type": "azurerm_storage_account",
      "name": "compliant_lake",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "name": "datalakeprod",
          "https_traffic_only_enabled": true
        }
      }
    }
  ]
}`

// TestCLI_Verify_ValidPolicy tests `tf-sim verify` against the valid multi-cloud policy and schema.
func TestCLI_Verify_ValidPolicy(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	code := Execute(ctx, []string{
		"verify",
		"--policy", policyPath,
		"--schema", schemaPath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != ExitOK {
		t.Fatalf("expected ExitOK (%d), got %d; stderr: %s; stdout: %s", ExitOK, code, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var res model.VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal VerificationResult JSON: %v\nOutput: %s", err, stdout.String())
	}
	if !res.Valid {
		t.Errorf("expected res.Valid == true, got false (diagnostics: %+v)", res.Diagnostics)
	}
}

// TestCLI_Verify_BrokenFailOpenPolicy tests `tf-sim verify` against a fail-open policy containing an attribute typo.
func TestCLI_Verify_BrokenFailOpenPolicy(t *testing.T) {
	ctx := context.Background()
	var stdout, stderr bytes.Buffer

	policyPath := filepath.Join("..", "..", "testdata", "policies", "broken_fail_open.rego")
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	code := Execute(ctx, []string{
		"verify",
		"--policy", policyPath,
		"--schema", schemaPath,
		"--format", "table",
	}, &stdout, &stderr)

	if code != ExitViolation {
		t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s; stdout: %s", ExitViolation, code, stderr.String(), stdout.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "https_only_enabled") {
		t.Errorf("expected stdout to contain diagnostic for 'https_only_enabled', got:\n%s", out)
	}
	if !strings.Contains(out, "azurerm_storage_account") {
		t.Errorf("expected stdout to contain 'azurerm_storage_account', got:\n%s", out)
	}
}

// TestCLI_Eval_ViolationsAndClean tests `tf-sim eval` on both non-compliant and compliant Terraform plans.
func TestCLI_Eval_ViolationsAndClean(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	t.Run("NonCompliantPlan_ReturnsExitViolation", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

		code := Execute(ctx, []string{
			"eval",
			"--policy", policyPath,
			"--plan", planPath,
			"--format", "table",
		}, &stdout, &stderr)

		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "AWS-S3-ENCRYPT-001") {
			t.Errorf("expected stdout to report AWS-S3-ENCRYPT-001, got:\n%s", stdout.String())
		}
	})

	t.Run("CompliantPlan_ReturnsExitOK", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmpDir := t.TempDir()
		planPath := filepath.Join(tmpDir, "compliant_plan.json")
		if err := os.WriteFile(planPath, []byte(compliantPlanJSON), 0o600); err != nil {
			t.Fatalf("failed to write compliant plan: %v", err)
		}

		code := Execute(ctx, []string{
			"eval",
			"--policy", policyPath,
			"--plan", planPath,
			"--repo", "compliant-repo",
			"--format", "json",
		}, &stdout, &stderr)

		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}

		var res model.EvalResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
		}
		if !res.Passed || len(res.Violations) != 0 {
			t.Errorf("expected Passed == true and 0 violations, got: %+v", res)
		}
	})
}

// TestCLI_Backtest_MultiCloudCorpus tests `tf-sim backtest` against the multi-cloud corpus and a clean corpus.
func TestCLI_Backtest_MultiCloudCorpus(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	t.Run("MultiCloudCorpus_Blocked", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		plansDir := filepath.Join("..", "..", "testdata", "plans")

		code := Execute(ctx, []string{
			"backtest",
			"--policy", policyPath,
			"--plans-dir", plansDir,
			"--concurrency", "2",
			"--format", "json",
		}, &stdout, &stderr)

		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
		}

		var rep model.BlastRadiusReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to unmarshal BlastRadiusReport JSON: %v\nOutput: %s", err, stdout.String())
		}
		if rep.TotalReposAnalyzed != 3 {
			t.Errorf("expected TotalReposAnalyzed == 3, got %d", rep.TotalReposAnalyzed)
		}
		if rep.BlockedPlansCount != 3 {
			t.Errorf("expected BlockedPlansCount == 3, got %d", rep.BlockedPlansCount)
		}
		if rep.TotalViolations != 3 {
			t.Errorf("expected TotalViolations == 3, got %d", rep.TotalViolations)
		}
	})

	t.Run("CompliantCorpus_Clean", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "clean_repo.json"), []byte(compliantPlanJSON), 0o600); err != nil {
			t.Fatalf("failed to write clean_repo.json: %v", err)
		}

		code := Execute(ctx, []string{
			"backtest",
			"--policy", policyPath,
			"--plans-dir", tmpDir,
			"--format", "json",
		}, &stdout, &stderr)

		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
	})
}

// TestCLI_Remediate_DryRunAndWrite tests `tf-sim remediate` both in default dry-run mode and with `--write`.
func TestCLI_Remediate_DryRunAndWrite(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	t.Run("DryRun_Markdown_DoesNotModifyDisk", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
		tfDir := filepath.Join("..", "..", "testdata", "repos", "payments-aws")
		tfFile := filepath.Join(tfDir, "main.tf")

		beforeBytes, err := os.ReadFile(tfFile)
		if err != nil {
			t.Fatalf("failed to read %s before test: %v", tfFile, err)
		}

		code := Execute(ctx, []string{
			"remediate",
			"--policy", policyPath,
			"--plan", planPath,
			"--tf-dir", tfDir,
			"--format", "markdown",
		}, &stdout, &stderr)

		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}

		out := stdout.String()
		if !strings.Contains(out, "```diff") {
			t.Errorf("expected markdown output to contain ```diff fenced block, got:\n%s", out)
		}
		if !strings.Contains(out, `sse_algorithm = "aws:kms"`) {
			t.Errorf("expected diff output to contain sse_algorithm = \"aws:kms\", got:\n%s", out)
		}

		afterBytes, err := os.ReadFile(tfFile)
		if err != nil {
			t.Fatalf("failed to read %s after test: %v", tfFile, err)
		}
		if !bytes.Equal(beforeBytes, afterBytes) {
			t.Errorf("dry-run remediate unexpectedly modified %s on disk", tfFile)
		}
	})

	t.Run("WriteInPlace_UpdatesHCLFile", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
		srcTfFile := filepath.Join("..", "..", "testdata", "repos", "data-azure", "main.tf")

		srcBytes, err := os.ReadFile(srcTfFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", srcTfFile, err)
		}

		tmpDir := t.TempDir()
		dstTfFile := filepath.Join(tmpDir, "main.tf")
		if err := os.WriteFile(dstTfFile, srcBytes, 0o600); err != nil {
			t.Fatalf("failed to write temp main.tf: %v", err)
		}

		code := Execute(ctx, []string{
			"remediate",
			"--policy", policyPath,
			"--plan", planPath,
			"--tf-dir", tmpDir,
			"--write",
			"--format", "json",
		}, &stdout, &stderr)

		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}

		updatedBytes, err := os.ReadFile(dstTfFile)
		if err != nil {
			t.Fatalf("failed to read updated main.tf: %v", err)
		}
		if strings.Contains(string(updatedBytes), "https_traffic_only_enabled = false") {
			t.Errorf("expected https_traffic_only_enabled = false to be remediated on disk, got:\n%s", string(updatedBytes))
		}
		if !strings.Contains(string(updatedBytes), "https_traffic_only_enabled = true") {
			t.Errorf("expected https_traffic_only_enabled = true on disk, got:\n%s", string(updatedBytes))
		}
	})
}

// TestCLI_MissingRequiredFlags validates that omitting required CLI flags returns ExitError (2).
func TestCLI_MissingRequiredFlags(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "Verify_MissingPolicy",
			args: []string{"verify"},
		},
		{
			name: "Eval_MissingPlan",
			args: []string{"eval", "--policy", policyPath},
		},
		{
			name: "Eval_MissingPolicy",
			args: []string{"eval", "--plan", planPath},
		},
		{
			name: "Backtest_MissingPlansDir",
			args: []string{"backtest", "--policy", policyPath},
		},
		{
			name: "Remediate_MissingTfDir",
			args: []string{"remediate", "--policy", policyPath, "--plan", planPath},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, tc.args, &stdout, &stderr)
			if code != ExitError {
				t.Errorf("expected ExitError (%d) for %v, got %d", ExitError, tc.args, code)
			}
			if stderr.Len() == 0 {
				t.Errorf("expected non-empty error message on stderr for %v", tc.args)
			}
		})
	}
}

// TestCLI_UnsupportedFormatAndMissingFiles validates that bad format flags or unreadable files return ExitError (2).
func TestCLI_UnsupportedFormatAndMissingFiles(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "Verify_UnsupportedFormatYAML",
			args: []string{"verify", "--policy", policyPath, "--format", "yaml"},
		},
		{
			name: "Verify_MissingPolicyFile",
			args: []string{"verify", "--policy", "nonexistent_policy.rego"},
		},
		{
			name: "Verify_MissingSchemaFile",
			args: []string{"verify", "--policy", policyPath, "--schema", "nonexistent_schema.json"},
		},
		{
			name: "Eval_MissingPlanFile",
			args: []string{"eval", "--policy", policyPath, "--plan", "nonexistent_plan.json"},
		},
		{
			name: "Eval_UnsupportedFormatYAML",
			args: []string{"eval", "--policy", policyPath, "--plan", planPath, "--format", "yaml"},
		},
		{
			name: "Backtest_MissingPlansDir",
			args: []string{"backtest", "--policy", policyPath, "--plans-dir", "nonexistent_dir"},
		},
		{
			name: "Remediate_MissingTfDir",
			args: []string{"remediate", "--policy", policyPath, "--plan", planPath, "--tf-dir", "nonexistent_tf_dir"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, tc.args, &stdout, &stderr)
			if code != ExitError {
				t.Errorf("expected ExitError (%d) for %v, got %d", ExitError, tc.args, code)
			}
		})
	}
}

// TestCLI_HelpAndUnknownCommand tests `--help` and unknown subcommands.
func TestCLI_HelpAndUnknownCommand(t *testing.T) {
	ctx := context.Background()

	t.Run("HelpFlag_ReturnsExitOK", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"--help"}, &stdout, &stderr)
		if code != ExitOK {
			t.Errorf("expected ExitOK (%d) for --help, got %d", ExitOK, code)
		}
		if !strings.Contains(stdout.String(), "tf-sim") {
			t.Errorf("expected help output to mention tf-sim, got:\n%s", stdout.String())
		}
	})

	t.Run("UnknownCommand_ReturnsExitError", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"unknown-subcommand"}, &stdout, &stderr)
		if code != ExitError {
			t.Errorf("expected ExitError (%d) for unknown-subcommand, got %d", ExitError, code)
		}
	})
}
