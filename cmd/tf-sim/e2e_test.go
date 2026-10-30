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

// resolveTestdataPath finds the testdata directory whether tests run from the repo root or cmd/tf-sim.
func resolveTestdataPath(t *testing.T, relParts ...string) string {
	t.Helper()
	candidateCmd := filepath.Join(append([]string{"..", "..", "testdata"}, relParts...)...)
	if _, err := os.Stat(candidateCmd); err == nil {
		return candidateCmd
	}
	candidateRoot := filepath.Join(append([]string{"testdata"}, relParts...)...)
	if _, err := os.Stat(candidateRoot); err == nil {
		return candidateRoot
	}
	t.Fatalf("could not locate testdata for parts %v", relParts)
	return ""
}

// createPatchedPlanFile copies a source plan JSON file and updates the designated resource's
// change.after map using the provided patch function, writing it to destPath.
func createPatchedPlanFile(t *testing.T, srcPlanPath, destPlanPath, targetAddress string, patchFn func(after map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(srcPlanPath)
	if err != nil {
		t.Fatalf("failed to read plan %s: %v", srcPlanPath, err)
	}

	var planMap map[string]any
	if err := json.Unmarshal(data, &planMap); err != nil {
		t.Fatalf("failed to unmarshal plan JSON: %v", err)
	}

	changes, ok := planMap["resource_changes"].([]any)
	if !ok {
		t.Fatalf("plan JSON missing resource_changes array")
	}

	found := false
	for _, item := range changes {
		rc, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if rc["address"] == targetAddress {
			change, ok := rc["change"].(map[string]any)
			if !ok {
				t.Fatalf("resource change missing change object for %s", targetAddress)
			}
			after, ok := change["after"].(map[string]any)
			if !ok || after == nil {
				after = make(map[string]any)
			}
			patchFn(after)
			change["after"] = after
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("resource address %s not found in %s", targetAddress, srcPlanPath)
	}

	outBytes, err := json.MarshalIndent(planMap, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal patched plan JSON: %v", err)
	}

	if err := os.WriteFile(destPlanPath, outBytes, 0o600); err != nil {
		t.Fatalf("failed to write patched plan to %s: %v", destPlanPath, err)
	}
}

// TestE2E_ClosedLoopLifecycle executes the complete end-to-end lifecycle across
// AWS, Azure, and GCP multi-cloud infrastructure:
//  1. Verify (Fail-Open Gate): validates provider schema checks reject typos and accept valid policies.
//  2. Backtest (Blast Radius): validates cross-repo impact simulation across historical plans.
//  3. Eval (Pre-Remediation): evaluates non-compliant cloud plans and asserts ExitViolation (1).
//  4. Remediate (--write): executes surgical AST mutations in-place in isolated workspaces.
//  5. Eval (Post-Remediation): evaluates the patched infrastructure state and asserts ExitOK (0).
func TestE2E_ClosedLoopLifecycle(t *testing.T) {
	ctx := context.Background()

	validPolicyPath := resolveTestdataPath(t, "policies", "storage_encryption.rego")
	brokenPolicyPath := resolveTestdataPath(t, "policies", "broken_fail_open.rego")
	schemaPath := resolveTestdataPath(t, "schemas", "multicloud_schema.json")
	plansDir := resolveTestdataPath(t, "plans")

	// -------------------------------------------------------------------------
	// Step 1: Verify (Fail-Open Gate)
	// -------------------------------------------------------------------------
	t.Run("Stage1_Verify_FailOpenGate", func(t *testing.T) {
		t.Run("BrokenPolicy_FailsWithExitViolation", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"verify",
				"--policy", brokenPolicyPath,
				"--schema", schemaPath,
				"--format", "json",
			}, &stdout, &stderr)

			if code != ExitViolation {
				t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
			}

			var res model.VerificationResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal VerificationResult JSON: %v\nOutput: %s", err, stdout.String())
			}
			if res.Valid {
				t.Fatalf("expected res.Valid == false for broken policy with typo")
			}

			foundAzureTypo := false
			foundAWSTypo := false
			for _, diag := range res.Diagnostics {
				if diag.ResourceType == "azurerm_storage_account" && diag.InvalidPath == "https_only_enabled" {
					foundAzureTypo = true
				}
				if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "invalid_encrypt" {
					foundAWSTypo = true
				}
			}
			if !foundAzureTypo {
				t.Errorf("expected diagnostic for azurerm_storage_account.https_only_enabled, got: %+v", res.Diagnostics)
			}
			if !foundAWSTypo {
				t.Errorf("expected diagnostic for aws_s3_bucket.invalid_encrypt, got: %+v", res.Diagnostics)
			}
		})

		t.Run("ValidPolicy_PassesWithExitOK", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"verify",
				"--policy", validPolicyPath,
				"--schema", schemaPath,
				"--format", "json",
			}, &stdout, &stderr)

			if code != ExitOK {
				t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
			}

			var res model.VerificationResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal VerificationResult JSON: %v\nOutput: %s", err, stdout.String())
			}
			if !res.Valid || len(res.Diagnostics) != 0 {
				t.Fatalf("expected res.Valid == true and 0 diagnostics, got valid=%v diags=%+v", res.Valid, res.Diagnostics)
			}
		})
	})

	// -------------------------------------------------------------------------
	// Step 2: Backtest (Blast Radius)
	// -------------------------------------------------------------------------
	t.Run("Stage2_Backtest_BlastRadiusSimulation", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"backtest",
			"--policy", validPolicyPath,
			"--plans-dir", plansDir,
			"--concurrency", "2",
			"--format", "json",
		}, &stdout, &stderr)

		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d) due to blocked historical plans, got %d; stderr: %s", ExitViolation, code, stderr.String())
		}

		var rep model.BlastRadiusReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to unmarshal BlastRadiusReport JSON: %v\nOutput: %s", err, stdout.String())
		}

		if rep.TotalReposAnalyzed != 3 {
			t.Errorf("expected TotalReposAnalyzed == 3, got %d", rep.TotalReposAnalyzed)
		}
		if rep.ImpactedReposCount != 3 {
			t.Errorf("expected ImpactedReposCount == 3, got %d", rep.ImpactedReposCount)
		}
		if rep.TotalPlansAnalyzed != 3 {
			t.Errorf("expected TotalPlansAnalyzed == 3, got %d", rep.TotalPlansAnalyzed)
		}
		if rep.BlockedPlansCount != 3 {
			t.Errorf("expected BlockedPlansCount == 3, got %d", rep.BlockedPlansCount)
		}
		if rep.TotalViolations != 3 {
			t.Errorf("expected TotalViolations == 3, got %d", rep.TotalViolations)
		}

		expectedProviders := map[string]int{
			"aws":     1,
			"azurerm": 1,
			"google":  1,
		}
		for prov, expCount := range expectedProviders {
			if rep.BreakdownByProvider[prov] != expCount {
				t.Errorf("expected breakdown[%s] == %d, got %d", prov, expCount, rep.BreakdownByProvider[prov])
			}
		}

		if len(rep.RepoImpacts) != 3 {
			t.Errorf("expected 3 RepoImpact entries, got %d", len(rep.RepoImpacts))
		}
	})

	// -------------------------------------------------------------------------
	// Steps 3, 4, 5: Cloud-by-Cloud Closed-Loop Remediation & Re-Evaluation
	// -------------------------------------------------------------------------
	cases := []struct {
		cloudProvider          string
		repoName               string
		planFileName           string
		repoSubDir             string
		expectedRuleID         string
		expectedSeverity       string
		expectedResourceAddr   string
		expectedResourceType   string
		expectedResourceName   string
		expectedAttrPath       []string
		expectedSuggestedVal   any
		requiredHCLSubstrings  []string
		forbiddenHCLSubstrings []string
		preservedComments      []string
		patchAfterFn           func(after map[string]any)
	}{
		{
			cloudProvider:        "AWS",
			repoName:             "payments-aws",
			planFileName:         "repo_payments_aws.json",
			repoSubDir:           "payments-aws",
			expectedRuleID:       "AWS-S3-ENCRYPT-001",
			expectedSeverity:     "HIGH",
			expectedResourceAddr: "aws_s3_bucket.unencrypted_reports",
			expectedResourceType: "aws_s3_bucket",
			expectedResourceName: "unencrypted_reports",
			expectedAttrPath: []string{
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algorithm",
			},
			expectedSuggestedVal: "aws:kms",
			requiredHCLSubstrings: []string{
				`server_side_encryption_configuration {`,
				`rule {`,
				`apply_server_side_encryption_by_default {`,
				`sse_algorithm = "aws:kms"`,
			},
			forbiddenHCLSubstrings: nil,
			preservedComments: []string{
				"# Payments Service - AWS Storage Infrastructure",
				"# Managed by Platform Engineering",
				"# Monthly financial reports bucket (currently missing server-side encryption)",
				"# Retain bucket name for downstream billing export",
			},
			patchAfterFn: func(after map[string]any) {
				after["server_side_encryption_configuration"] = []any{
					map[string]any{
						"rule": []any{
							map[string]any{
								"apply_server_side_encryption_by_default": []any{
									map[string]any{
										"sse_algorithm": "aws:kms",
									},
								},
							},
						},
					},
				}
			},
		},
		{
			cloudProvider:        "Azure",
			repoName:             "data-azure",
			planFileName:         "repo_data_azure.json",
			repoSubDir:           "data-azure",
			expectedRuleID:       "AZURE-STORAGE-HTTPS-001",
			expectedSeverity:     "HIGH",
			expectedResourceAddr: "azurerm_storage_account.insecure_transfer",
			expectedResourceType: "azurerm_storage_account",
			expectedResourceName: "insecure_transfer",
			expectedAttrPath:     []string{"https_traffic_only_enabled"},
			expectedSuggestedVal: true,
			requiredHCLSubstrings: []string{
				`https_traffic_only_enabled = true`,
			},
			forbiddenHCLSubstrings: []string{
				`https_traffic_only_enabled = false`,
			},
			preservedComments: []string{
				"# Data Platform - Azure Storage Infrastructure",
				"# Managed by Data Engineering",
				"# Legacy data ingestion storage account (non-compliant HTTPS setting)",
				"# Legacy toggle - must be remediated to true",
			},
			patchAfterFn: func(after map[string]any) {
				after["https_traffic_only_enabled"] = true
			},
		},
		{
			cloudProvider:        "GCP",
			repoName:             "ml-gcp",
			planFileName:         "repo_ml_gcp.json",
			repoSubDir:           "ml-gcp",
			expectedRuleID:       "GCP-STORAGE-UBLA-001",
			expectedSeverity:     "MEDIUM",
			expectedResourceAddr: "google_storage_bucket.open_training_data",
			expectedResourceType: "google_storage_bucket",
			expectedResourceName: "open_training_data",
			expectedAttrPath:     []string{"uniform_bucket_level_access"},
			expectedSuggestedVal: true,
			requiredHCLSubstrings: []string{
				`uniform_bucket_level_access = true`,
			},
			forbiddenHCLSubstrings: []string{
				`uniform_bucket_level_access = false`,
			},
			preservedComments: []string{
				"# Machine Learning Platform - GCP Cloud Storage Infrastructure",
				"# Managed by MLOps Team",
				"# Raw training dataset bucket (non-compliant ACL access setting)",
				"# Must enforce uniform bucket-level IAM access",
			},
			patchAfterFn: func(after map[string]any) {
				after["uniform_bucket_level_access"] = true
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("Cloud_"+tc.cloudProvider, func(t *testing.T) {
			planPath := resolveTestdataPath(t, "plans", tc.planFileName)
			srcRepoDir := resolveTestdataPath(t, "repos", tc.repoSubDir)
			srcMainTf := filepath.Join(srcRepoDir, "main.tf")

			// Setup an isolated temporary workspace for this cloud
			tmpDir := t.TempDir()
			dstMainTf := filepath.Join(tmpDir, "main.tf")

			originalContent, err := os.ReadFile(srcMainTf)
			if err != nil {
				t.Fatalf("failed to read source main.tf: %v", err)
			}
			if err := os.WriteFile(dstMainTf, originalContent, 0o600); err != nil {
				t.Fatalf("failed to copy main.tf to temp dir: %v", err)
			}

			// -----------------------------------------------------------------
			// Step 3: Eval (Pre-Remediation)
			// -----------------------------------------------------------------
			t.Run("Stage3_Eval_PreRemediation_FlagsViolation", func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Execute(ctx, []string{
					"eval",
					"--policy", validPolicyPath,
					"--plan", planPath,
					"--repo", tc.repoName,
					"--format", "json",
				}, &stdout, &stderr)

				if code != ExitViolation {
					t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
				}

				var res model.EvalResult
				if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
					t.Fatalf("failed to unmarshal EvalResult JSON: %v\nOutput: %s", err, stdout.String())
				}

				if res.Passed {
					t.Fatalf("expected res.Passed == false for non-compliant plan")
				}
				if len(res.Violations) != 1 {
					t.Fatalf("expected exactly 1 violation, got %d: %+v", len(res.Violations), res.Violations)
				}

				v := res.Violations[0]
				if v.RuleID != tc.expectedRuleID {
					t.Errorf("expected RuleID %s, got %s", tc.expectedRuleID, v.RuleID)
				}
				if v.Severity != tc.expectedSeverity {
					t.Errorf("expected Severity %s, got %s", tc.expectedSeverity, v.Severity)
				}
				if v.ResourceAddress != tc.expectedResourceAddr {
					t.Errorf("expected ResourceAddress %s, got %s", tc.expectedResourceAddr, v.ResourceAddress)
				}
				if v.ResourceType != tc.expectedResourceType {
					t.Errorf("expected ResourceType %s, got %s", tc.expectedResourceType, v.ResourceType)
				}
				if v.ResourceName != tc.expectedResourceName {
					t.Errorf("expected ResourceName %s, got %s", tc.expectedResourceName, v.ResourceName)
				}
				if v.Remediation == nil {
					t.Fatalf("expected non-nil Remediation in violation")
				}

				if len(v.Remediation.AttributePath) != len(tc.expectedAttrPath) {
					t.Fatalf("expected AttributePath length %d, got %d (%v)", len(tc.expectedAttrPath), len(v.Remediation.AttributePath), v.Remediation.AttributePath)
				}
				for i, seg := range tc.expectedAttrPath {
					if v.Remediation.AttributePath[i] != seg {
						t.Errorf("expected AttributePath[%d] == %s, got %s", i, seg, v.Remediation.AttributePath[i])
					}
				}
				if v.Remediation.SuggestedVal != tc.expectedSuggestedVal {
					t.Errorf("expected SuggestedVal %v, got %v", tc.expectedSuggestedVal, v.Remediation.SuggestedVal)
				}
			})

			// -----------------------------------------------------------------
			// Step 4: Remediate (--write)
			// -----------------------------------------------------------------
			t.Run("Stage4_Remediate_WriteInPlace_PatchesHCL", func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Execute(ctx, []string{
					"remediate",
					"--policy", validPolicyPath,
					"--plan", planPath,
					"--tf-dir", tmpDir,
					"--write",
					"--format", "markdown",
				}, &stdout, &stderr)

				if code != ExitOK {
					t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
				}

				out := stdout.String()
				// Verify unified diff structure
				if !strings.Contains(out, "```diff") {
					t.Errorf("expected diff codeblock in markdown output, got:\n%s", out)
				}
				if !strings.Contains(out, "--- a/main.tf") || !strings.Contains(out, "+++ b/main.tf") {
					t.Errorf("expected unified diff file headers (--- a/main.tf, +++ b/main.tf), got:\n%s", out)
				}
				if !strings.Contains(out, "@@ ") {
					t.Errorf("expected hunk header (@@ ... @@) in diff output, got:\n%s", out)
				}

				// Verify patched file on disk
				patchedBytes, err := os.ReadFile(dstMainTf)
				if err != nil {
					t.Fatalf("failed to read patched main.tf from temp dir: %v", err)
				}
				patchedStr := string(patchedBytes)

				for _, req := range tc.requiredHCLSubstrings {
					if !strings.Contains(patchedStr, req) {
						t.Errorf("expected patched main.tf to contain %q, but got:\n%s", req, patchedStr)
					}
				}
				for _, fbd := range tc.forbiddenHCLSubstrings {
					if strings.Contains(patchedStr, fbd) {
						t.Errorf("expected patched main.tf to NOT contain %q, but got:\n%s", fbd, patchedStr)
					}
				}
				for _, comment := range tc.preservedComments {
					if !strings.Contains(patchedStr, comment) {
						t.Errorf("expected patched main.tf to preserve comment %q, but got:\n%s", comment, patchedStr)
					}
				}
			})

			// -----------------------------------------------------------------
			// Step 5: Closed-Loop Re-Evaluation (Post-Remediation)
			// -----------------------------------------------------------------
			t.Run("Stage5_Eval_PostRemediation_ReturnsExitOK", func(t *testing.T) {
				// Construct the post-remediation plan JSON reflecting the applied HCL fixes
				postRemediationPlanPath := filepath.Join(tmpDir, "post_remediation_plan.json")
				createPatchedPlanFile(t, planPath, postRemediationPlanPath, tc.expectedResourceAddr, tc.patchAfterFn)

				var stdout, stderr bytes.Buffer
				code := Execute(ctx, []string{
					"eval",
					"--policy", validPolicyPath,
					"--plan", postRemediationPlanPath,
					"--repo", tc.repoName + "-remediated",
					"--format", "json",
				}, &stdout, &stderr)

				if code != ExitOK {
					t.Fatalf("expected ExitOK (%d) post-remediation, got %d; stderr: %s; stdout: %s", ExitOK, code, stderr.String(), stdout.String())
				}

				var res model.EvalResult
				if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
					t.Fatalf("failed to unmarshal post-remediation EvalResult JSON: %v\nOutput: %s", err, stdout.String())
				}

				if !res.Passed {
					t.Errorf("expected res.Passed == true after remediation, got false (violations: %+v)", res.Violations)
				}
				if len(res.Violations) != 0 {
					t.Errorf("expected 0 violations post-remediation, got %d: %+v", len(res.Violations), res.Violations)
				}
			})
		})
	}
}
