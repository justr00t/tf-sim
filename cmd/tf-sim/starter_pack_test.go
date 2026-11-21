package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/policy"
)

var (
	allAWSRuleIDs = []string{
		"aws-s3-pab-acls",
		"aws-s3-pab-policy",
		"aws-s3-pab-ignore",
		"aws-s3-pab-restrict",
		"aws-s3-sse-kms",
		"aws-s3-versioning",
		"aws-rds-encrypt",
		"aws-rds-public",
		"aws-rds-iam-auth",
		"aws-ebs-encrypt",
		"aws-ec2-ebs-opt",
		"aws-kms-rotation",
	}
	allAzureRuleIDs = []string{
		"azure-storage-https",
		"azure-storage-tls",
		"azure-mssql-tls",
		"azure-psql-flex-public",
		"azure-psql-flex-backup",
		"azure-kv-softdel",
		"azure-kv-purge",
		"azure-kv-rbac",
	}
	allGCPRuleIDs = []string{
		"gcp-storage-ubla",
		"gcp-storage-public",
		"gcp-sql-ssl",
		"gcp-sql-backup",
		"gcp-compute-shielded",
		"gcp-compute-ip-fwd",
		"gcp-kms-rotation",
		"gcp-firewall-log",
	}
)

func TestCLI_Packs_FormatsAndErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("DefaultTableFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"packs"}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"aws", "azure", "gcp", "all", "12", "8", "28"} {
			if !strings.Contains(out, want) {
				t.Errorf("expected table output to contain %q, got:\n%s", want, out)
			}
		}
	})

	t.Run("ExplicitTableFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"packs", "--format", "table"}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"aws", "azure", "gcp", "all"} {
			if !strings.Contains(out, want) {
				t.Errorf("expected table output to contain %q, got:\n%s", want, out)
			}
		}
	})

	t.Run("JSONFormat", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"packs", "--format", "json"}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("expected empty stderr, got: %s", stderr.String())
		}

		var packs []policy.PackInfo
		if err := json.Unmarshal(stdout.Bytes(), &packs); err != nil {
			t.Fatalf("failed to unmarshal packs JSON: %v\nOutput:\n%s", err, stdout.String())
		}
		if len(packs) != 4 {
			t.Fatalf("expected 4 packs, got %d: %+v", len(packs), packs)
		}

		wantOrder := []struct {
			name  string
			files int
			rules int
		}{
			{"aws", 5, 12},
			{"azure", 3, 8},
			{"gcp", 5, 8},
			{"all", 13, 28},
		}
		for i, w := range wantOrder {
			if packs[i].Name != w.name {
				t.Errorf("packs[%d].Name = %q, want %q", i, packs[i].Name, w.name)
			}
			if packs[i].FileCount != w.files {
				t.Errorf("pack %q FileCount = %d, want %d", w.name, packs[i].FileCount, w.files)
			}
			if packs[i].RuleCount != w.rules {
				t.Errorf("pack %q RuleCount = %d, want %d", w.name, packs[i].RuleCount, w.rules)
			}
		}
	})

	t.Run("InvalidFormat_Exits2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{"packs", "--format", "yaml"}, &stdout, &stderr)
		if code != ExitError {
			t.Fatalf("expected ExitError (%d), got %d; stdout: %s; stderr: %s", ExitError, code, stdout.String(), stderr.String())
		}
		if stderr.Len() == 0 {
			t.Error("expected non-empty stderr for invalid format")
		}
	})
}

func TestCLI_Verify_StarterPacksAndDirectoryLoading(t *testing.T) {
	ctx := context.Background()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "starter_pack_schema.json")
	passDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass")
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")
	awsPoliciesDir := filepath.Join("..", "..", "policies", "aws")

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "PackAll_WithSchemaAndPassFailFixtures",
			args: []string{
				"verify",
				"--pack", "all",
				"--schema", schemaPath,
				"--pass-fixtures", passDir,
				"--fail-fixtures", failDir,
				"--format", "json",
			},
		},
		{
			name: "PackAWS_WithAWSFixtures",
			args: []string{
				"verify",
				"--pack", "aws",
				"--schema", schemaPath,
				"--pass-fixtures", filepath.Join(passDir, "aws_pass.json"),
				"--fail-fixtures", filepath.Join(failDir, "aws_fail.json"),
				"--format", "json",
			},
		},
		{
			name: "PackAzure_WithAzureFixtures",
			args: []string{
				"verify",
				"--pack", "azure",
				"--schema", schemaPath,
				"--pass-fixtures", filepath.Join(passDir, "azure_pass.json"),
				"--fail-fixtures", filepath.Join(failDir, "azure_fail.json"),
				"--format", "json",
			},
		},
		{
			name: "PackGCP_WithGCPFixtures",
			args: []string{
				"verify",
				"--pack", "gcp",
				"--schema", schemaPath,
				"--pass-fixtures", filepath.Join(passDir, "gcp_pass.json"),
				"--fail-fixtures", filepath.Join(failDir, "gcp_fail.json"),
				"--format", "json",
			},
		},
		{
			name: "PolicyDirectory_PoliciesAWS",
			args: []string{
				"verify",
				"--policy", awsPoliciesDir,
				"--schema", schemaPath,
				"--pass-fixtures", filepath.Join(passDir, "aws_pass.json"),
				"--fail-fixtures", filepath.Join(failDir, "aws_fail.json"),
				"--format", "json",
			},
		},
		{
			name: "MixedPolicyDirAndPack",
			args: []string{
				"verify",
				"--policy", awsPoliciesDir,
				"--pack", "gcp",
				"--schema", schemaPath,
				"--format", "json",
			},
		},
		{
			name: "DuplicatePacks_AWSAndAll",
			args: []string{
				"verify",
				"--pack", "aws",
				"--pack", "all",
				"--schema", schemaPath,
				"--format", "json",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, tc.args, &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("expected ExitOK (%d), got %d\nstderr: %s\nstdout: %s", ExitOK, code, stderr.String(), stdout.String())
			}

			var res model.VerificationResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal VerificationResult JSON: %v\nOutput: %s", err, stdout.String())
			}
			if !res.Valid || len(res.Diagnostics) != 0 {
				t.Errorf("expected Valid == true and 0 diagnostics, got Valid=%v Diagnostics=%+v", res.Valid, res.Diagnostics)
			}
		})
	}
}

func TestCLI_Eval_StarterPacks_All28Rules(t *testing.T) {
	ctx := context.Background()
	passDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass")
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")
	awsPoliciesDir := filepath.Join("..", "..", "policies", "aws")

	cloudCases := []struct {
		name        string
		pack        string
		passFile    string
		failFile    string
		wantRuleIDs []string
	}{
		{
			name:        "AWS",
			pack:        "aws",
			passFile:    filepath.Join(passDir, "aws_pass.json"),
			failFile:    filepath.Join(failDir, "aws_fail.json"),
			wantRuleIDs: allAWSRuleIDs,
		},
		{
			name:        "Azure",
			pack:        "azure",
			passFile:    filepath.Join(passDir, "azure_pass.json"),
			failFile:    filepath.Join(failDir, "azure_fail.json"),
			wantRuleIDs: allAzureRuleIDs,
		},
		{
			name:        "GCP",
			pack:        "gcp",
			passFile:    filepath.Join(passDir, "gcp_pass.json"),
			failFile:    filepath.Join(failDir, "gcp_fail.json"),
			wantRuleIDs: allGCPRuleIDs,
		},
	}

	seenAcrossAllPack := make(map[string]bool)

	for _, tc := range cloudCases {
		t.Run(tc.name+"_PassFixture_Exits0", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"eval",
				"--pack", tc.pack,
				"--plan", tc.passFile,
				"--format", "json",
			}, &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("expected ExitOK (%d), got %d; stderr: %s; stdout: %s", ExitOK, code, stderr.String(), stdout.String())
			}

			var res model.EvalResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
			}
			if !res.Passed || len(res.Violations) != 0 {
				t.Errorf("expected 0 violations on %s pass fixture, got %+v", tc.name, res.Violations)
			}
		})

		t.Run(tc.name+"_FailFixture_Exits1_AllRulesDetected", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"eval",
				"--pack", tc.pack,
				"--plan", tc.failFile,
				"--format", "json",
			}, &stdout, &stderr)
			if code != ExitViolation {
				t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s; stdout: %s", ExitViolation, code, stderr.String(), stdout.String())
			}

			var res model.EvalResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
			}
			if res.Passed {
				t.Errorf("expected Passed == false on %s fail fixture", tc.name)
			}

			explicitHit := make(map[string]bool)
			missingHit := make(map[string]bool)
			for _, v := range res.Violations {
				if strings.Contains(v.ResourceAddress, "deleted_") {
					t.Errorf("delete-only resource %q triggered false violation %q", v.ResourceAddress, v.RuleID)
				}
				if strings.HasSuffix(v.ResourceAddress, ".explicit_bad") {
					explicitHit[v.RuleID] = true
				}
				if strings.HasSuffix(v.ResourceAddress, ".missing_attrs") {
					missingHit[v.RuleID] = true
				}
			}
			for _, ruleID := range tc.wantRuleIDs {
				if !explicitHit[ruleID] {
					t.Errorf("pack %q did not detect rule %q on explicit_bad resource", tc.pack, ruleID)
				}
				if !missingHit[ruleID] {
					t.Errorf("pack %q did not detect rule %q on missing_attrs resource (fail-closed check)", tc.pack, ruleID)
				}
			}
			if len(res.Violations) != len(tc.wantRuleIDs)*2 {
				t.Errorf("expected %d total violations (%d rules x 2), got %d", len(tc.wantRuleIDs)*2, len(tc.wantRuleIDs), len(res.Violations))
			}
		})

		t.Run("PackAll_On_"+tc.name+"_FailFixture", func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"eval",
				"--pack", "all",
				"--plan", tc.failFile,
				"--format", "json",
			}, &stdout, &stderr)
			if code != ExitViolation {
				t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
			}

			var res model.EvalResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
			}
			for _, v := range res.Violations {
				seenAcrossAllPack[v.RuleID] = true
			}
		})
	}

	// Confirm every single one of the 28 Rule IDs was detected under `--pack all`.
	all28 := make([]string, 0, 28)
	all28 = append(all28, allAWSRuleIDs...)
	all28 = append(all28, allAzureRuleIDs...)
	all28 = append(all28, allGCPRuleIDs...)
	for _, ruleID := range all28 {
		if !seenAcrossAllPack[ruleID] {
			t.Errorf("--pack all failed to detect rule %q across starter pack fail fixtures", ruleID)
		}
	}

	t.Run("DuplicatePackDeduplication_NoDuplicateViolations", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"eval",
			"--pack", "aws",
			"--pack", "all",
			"--plan", filepath.Join(failDir, "aws_fail.json"),
			"--format", "json",
		}, &stdout, &stderr)
		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
		}
		var res model.EvalResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
		}
		if len(res.Violations) != len(allAWSRuleIDs)*2 {
			t.Errorf("expected deduplicated %d violations, got %d", len(allAWSRuleIDs)*2, len(res.Violations))
		}
	})

	t.Run("DirectoryLoading_PoliciesAWS", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"eval",
			"--policy", awsPoliciesDir,
			"--plan", filepath.Join(failDir, "aws_fail.json"),
			"--format", "json",
		}, &stdout, &stderr)
		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s", ExitViolation, code, stderr.String())
		}
		var res model.EvalResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
		}
		if len(res.Violations) != len(allAWSRuleIDs)*2 {
			t.Errorf("expected %d violations from --policy policies/aws, got %d", len(allAWSRuleIDs)*2, len(res.Violations))
		}
	})

	t.Run("MixedPolicyDirAndPack_EvaluatesBoth", func(t *testing.T) {
		for _, pair := range []struct {
			planPath  string
			wantRules []string
		}{
			{filepath.Join(failDir, "aws_fail.json"), allAWSRuleIDs},
			{filepath.Join(failDir, "gcp_fail.json"), allGCPRuleIDs},
		} {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"eval",
				"--policy", awsPoliciesDir,
				"--pack", "gcp",
				"--plan", pair.planPath,
				"--format", "json",
			}, &stdout, &stderr)
			if code != ExitViolation {
				t.Fatalf("expected ExitViolation (%d) for %s, got %d; stderr: %s", ExitViolation, pair.planPath, code, stderr.String())
			}
			var res model.EvalResult
			if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
				t.Fatalf("failed to unmarshal EvalResult JSON: %v", err)
			}
			got := map[string]bool{}
			for _, v := range res.Violations {
				got[v.RuleID] = true
			}
			for _, r := range pair.wantRules {
				if !got[r] {
					t.Errorf("mixed --policy policies/aws --pack gcp missed rule %q on %s", r, pair.planPath)
				}
			}
		}
	})
}

func TestCLI_Backtest_StarterPackAll(t *testing.T) {
	ctx := context.Background()
	passDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass")
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")

	t.Run("FailFixturesDir_AggregatesAll3CloudsAndAll28Rules", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"backtest",
			"--pack", "all",
			"--plans-dir", failDir,
			"--concurrency", "3",
			"--format", "json",
		}, &stdout, &stderr)
		if code != ExitViolation {
			t.Fatalf("expected ExitViolation (%d), got %d; stderr: %s; stdout: %s", ExitViolation, code, stderr.String(), stdout.String())
		}

		var rep model.BlastRadiusReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to unmarshal BlastRadiusReport JSON: %v\nOutput: %s", err, stdout.String())
		}
		if rep.TotalReposAnalyzed != 3 || rep.BlockedPlansCount != 3 || rep.TotalViolations != 56 {
			t.Errorf("unexpected summary counts: repos=%d blocked=%d violations=%d",
				rep.TotalReposAnalyzed, rep.BlockedPlansCount, rep.TotalViolations)
		}
		for prov, want := range map[string]int{"aws": 24, "azurerm": 16, "google": 16} {
			if rep.BreakdownByProvider[prov] != want {
				t.Errorf("BreakdownByProvider[%q] = %d, want %d", prov, rep.BreakdownByProvider[prov], want)
			}
		}

		seen := make(map[string]bool)
		for _, impact := range rep.RepoImpacts {
			for _, v := range impact.Violations {
				seen[v.RuleID] = true
			}
		}
		all28 := append(append(append([]string{}, allAWSRuleIDs...), allAzureRuleIDs...), allGCPRuleIDs...)
		for _, r := range all28 {
			if !seen[r] {
				t.Errorf("backtest report missing rule %q", r)
			}
		}
	})

	t.Run("PassFixturesDir_ExitsOKWithZeroViolations", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"backtest",
			"--pack", "all",
			"--plans-dir", passDir,
			"--format", "json",
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s; stdout: %s", ExitOK, code, stderr.String(), stdout.String())
		}
		var rep model.BlastRadiusReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("failed to unmarshal BlastRadiusReport JSON: %v", err)
		}
		if rep.TotalViolations != 0 || rep.BlockedPlansCount != 0 {
			t.Errorf("expected 0 violations and 0 blocked plans, got violations=%d blocked=%d", rep.TotalViolations, rep.BlockedPlansCount)
		}
	})
}

func TestCLI_Remediate_StarterPack_All26PatchableRules(t *testing.T) {
	ctx := context.Background()
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")
	reposDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "repos")

	cloudCases := []struct {
		name               string
		cloud              string
		planFile           string
		wantPatchCount     int
		wantPatchedSubstrs []string
		wantPreserved      []string
	}{
		{
			name:           "AWS_All12PatchableRules",
			cloud:          "aws",
			planFile:       filepath.Join(failDir, "aws_fail.json"),
			wantPatchCount: 24, // 12 rules x (explicit_bad + missing_attrs)
			wantPatchedSubstrs: []string{
				"block_public_acls       = true",
				"block_public_policy     = true",
				"ignore_public_acls      = true",
				"restrict_public_buckets = true",
				`sse_algorithm = "aws:kms"`,
				`status = "Enabled"`,
				"storage_encrypted                   = true",
				"publicly_accessible                 = false",
				"iam_database_authentication_enabled = true",
				"encrypted         = true",
				"ebs_optimized = true",
				"enable_key_rotation = true",
			},
			wantPreserved: []string{
				"# Starter Policy Pack - AWS Non-Compliant Infrastructure Fixture",
			},
		},
		{
			name:           "Azure_All8PatchableRules",
			cloud:          "azure",
			planFile:       filepath.Join(failDir, "azure_fail.json"),
			wantPatchCount: 16, // 8 rules x (explicit_bad + missing_attrs)
			wantPatchedSubstrs: []string{
				"https_traffic_only_enabled = true",
				`min_tls_version            = "TLS1_2"`,
				`minimum_tls_version = "1.2"`,
				"public_network_access_enabled = false",
				"backup_retention_days         = 7",
				"soft_delete_retention_days = 90",
				"purge_protection_enabled   = true",
				"enable_rbac_authorization  = true",
			},
			wantPreserved: []string{
				"# Starter Policy Pack - Azure Non-Compliant Infrastructure Fixture",
			},
		},
		{
			name:           "GCP_6PatchableRulesAnd2NonPatchableSkipped",
			cloud:          "gcp",
			planFile:       filepath.Join(failDir, "gcp_fail.json"),
			wantPatchCount: 12, // 6 patchable rules x (explicit_bad + missing_attrs); 2 SQL rules cleanly skipped
			wantPatchedSubstrs: []string{
				"uniform_bucket_level_access = true",
				`public_access_prevention    = "enforced"`,
				"enable_secure_boot = true",
				"can_ip_forward = false",
				`rotation_period = "7776000s"`,
				`metadata = "INCLUDE_ALL_METADATA"`,
			},
			wantPreserved: []string{
				"# Starter Policy Pack - GCP Non-Compliant Infrastructure Fixture",
				`ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"`,
				"enabled = false",
			},
		},
	}

	for _, tc := range cloudCases {
		t.Run(tc.name, func(t *testing.T) {
			srcMain := filepath.Join(reposDir, tc.cloud, "main.tf")
			srcBytes, err := os.ReadFile(srcMain)
			if err != nil {
				t.Fatalf("failed to read %s: %v", srcMain, err)
			}

			// Copy to t.TempDir() so git-tracked fixture repo is NEVER mutated.
			tmpDir := t.TempDir()
			dstMain := filepath.Join(tmpDir, "main.tf")
			if err := os.WriteFile(dstMain, srcBytes, 0o600); err != nil {
				t.Fatalf("failed to write temp main.tf: %v", err)
			}

			// 1. Dry-run JSON: validate patches, unified diffs, and non-mutation on disk.
			var dryStdout, dryStderr bytes.Buffer
			code := Execute(ctx, []string{
				"remediate",
				"--pack", "all",
				"--plan", tc.planFile,
				"--tf-dir", tmpDir,
				"--format", "json",
			}, &dryStdout, &dryStderr)
			if code != ExitOK {
				t.Fatalf("dry-run remediate expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, dryStderr.String())
			}

			var patches []model.RemediationPatch
			if err := json.Unmarshal(dryStdout.Bytes(), &patches); err != nil {
				t.Fatalf("failed to unmarshal RemediationPatch JSON: %v\nOutput: %s", err, dryStdout.String())
			}
			if len(patches) != tc.wantPatchCount {
				t.Fatalf("expected %d patches for %s, got %d", tc.wantPatchCount, tc.cloud, len(patches))
			}

			for i, patch := range patches {
				if patch.FilePath != "main.tf" {
					t.Errorf("patch[%d] FilePath = %q, want main.tf", i, patch.FilePath)
				}
				if !strings.Contains(patch.UnifiedDiff, "--- a/main.tf") ||
					!strings.Contains(patch.UnifiedDiff, "+++ b/main.tf") ||
					!strings.Contains(patch.UnifiedDiff, "@@") {
					t.Errorf("patch[%d] (%s) missing valid unified diff headers:\n%s", i, patch.ResourceAddress, patch.UnifiedDiff)
				}
				if _, diags := hclwrite.ParseConfig([]byte(patch.PatchedHCL), "main.tf", hcl.Pos{Line: 1, Column: 1}); diags.HasErrors() {
					t.Errorf("patch[%d] (%s) produced invalid HCL: %s", i, patch.ResourceAddress, diags.Error())
				}
				if strings.HasPrefix(patch.ResourceAddress, "google_sql_database_instance.") {
					t.Errorf("non-patchable resource %q should have been skipped, got patch: %+v", patch.ResourceAddress, patch)
				}
			}

			afterDryRun, err := os.ReadFile(dstMain)
			if err != nil {
				t.Fatalf("failed to read temp main.tf after dry-run: %v", err)
			}
			if !bytes.Equal(srcBytes, afterDryRun) {
				t.Errorf("dry-run remediate unexpectedly mutated temp main.tf on disk")
			}

			// 2. Write mode: apply all patches to temp copy and verify resulting HCL.
			var writeStdout, writeStderr bytes.Buffer
			writeCode := Execute(ctx, []string{
				"remediate",
				"--pack", "all",
				"--plan", tc.planFile,
				"--tf-dir", tmpDir,
				"--write",
				"--format", "json",
			}, &writeStdout, &writeStderr)
			if writeCode != ExitOK {
				t.Fatalf("--write remediate expected ExitOK (%d), got %d; stderr: %s", ExitOK, writeCode, writeStderr.String())
			}

			patchedBytes, err := os.ReadFile(dstMain)
			if err != nil {
				t.Fatalf("failed to read patched main.tf: %v", err)
			}
			if _, diags := hclwrite.ParseConfig(patchedBytes, "main.tf", hcl.Pos{Line: 1, Column: 1}); diags.HasErrors() {
				t.Fatalf("patched %s main.tf failed HCL parsing: %s\nContent:\n%s", tc.cloud, diags.Error(), string(patchedBytes))
			}

			patchedStr := string(patchedBytes)
			for _, sub := range tc.wantPatchedSubstrs {
				// Normalize whitespace around '=' when checking attributes so HCL alignment padding doesn't break intent assertions.
				if !containsNormalizedHCLAssignment(patchedStr, sub) {
					t.Errorf("patched %s main.tf missing expected remediated assignment %q\nContent:\n%s", tc.cloud, sub, patchedStr)
				}
			}
			for _, pres := range tc.wantPreserved {
				if !strings.Contains(patchedStr, pres) {
					t.Errorf("patched %s main.tf did not preserve %q\nContent:\n%s", tc.cloud, pres, patchedStr)
				}
			}
		})
	}

	t.Run("DryRunMarkdown_StarterPackAWS", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"remediate",
			"--pack", "aws",
			"--plan", filepath.Join(failDir, "aws_fail.json"),
			"--tf-dir", filepath.Join(reposDir, "aws"),
			"--format", "markdown",
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "```diff") {
			t.Errorf("expected markdown output to contain ```diff block, got:\n%s", out)
		}
		if !strings.Contains(out, `sse_algorithm = "aws:kms"`) {
			t.Errorf("expected markdown diff to contain sse_algorithm = \"aws:kms\", got:\n%s", out)
		}
	})
}

func TestCLI_StarterPack_ErrorCases(t *testing.T) {
	ctx := context.Background()
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")
	awsFailPlan := filepath.Join(failDir, "aws_fail.json")
	awsRepoDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "repos", "aws")
	emptyDir := t.TempDir()
	missingPath := filepath.Join(t.TempDir(), "does_not_exist.rego")

	tests := []struct {
		name             string
		args             []string
		wantStderrSubstr []string
	}{
		{
			name: "Verify_MissingBothPolicyAndPack",
			args: []string{"verify"},
		},
		{
			name: "Eval_MissingBothPolicyAndPack",
			args: []string{"eval", "--plan", awsFailPlan},
		},
		{
			name: "Backtest_MissingBothPolicyAndPack",
			args: []string{"backtest", "--plans-dir", failDir},
		},
		{
			name: "Remediate_MissingBothPolicyAndPack",
			args: []string{"remediate", "--plan", awsFailPlan, "--tf-dir", awsRepoDir},
		},
		{
			name:             "Verify_UnknownPack_ListsValidPacks",
			args:             []string{"verify", "--pack", "nonexistent"},
			wantStderrSubstr: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:             "Eval_UnknownPack_ListsValidPacks",
			args:             []string{"eval", "--pack", "nonexistent", "--plan", awsFailPlan},
			wantStderrSubstr: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:             "Backtest_UnknownPack_ListsValidPacks",
			args:             []string{"backtest", "--pack", "nonexistent", "--plans-dir", failDir},
			wantStderrSubstr: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:             "Remediate_UnknownPack_ListsValidPacks",
			args:             []string{"remediate", "--pack", "nonexistent", "--plan", awsFailPlan, "--tf-dir", awsRepoDir},
			wantStderrSubstr: []string{"aws", "azure", "gcp", "all"},
		},
		{
			name:             "Verify_EmptyPolicyDir",
			args:             []string{"verify", "--policy", emptyDir},
			wantStderrSubstr: []string{".rego"},
		},
		{
			name:             "Eval_EmptyPolicyDir",
			args:             []string{"eval", "--policy", emptyDir, "--plan", awsFailPlan},
			wantStderrSubstr: []string{".rego"},
		},
		{
			name: "Verify_NonexistentPolicyPath",
			args: []string{"verify", "--policy", missingPath},
		},
		{
			name: "Packs_InvalidFormat",
			args: []string{"packs", "--format", "invalid"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, tc.args, &stdout, &stderr)
			if code != ExitError {
				t.Fatalf("expected ExitError (%d) for %v, got %d\nstdout: %s\nstderr: %s",
					ExitError, tc.args, code, stdout.String(), stderr.String())
			}
			if stderr.Len() == 0 {
				t.Errorf("expected non-empty stderr for %v", tc.args)
			}
			errLower := strings.ToLower(stderr.String())
			for _, sub := range tc.wantStderrSubstr {
				if !strings.Contains(errLower, strings.ToLower(sub)) {
					t.Errorf("stderr %q does not contain expected substring %q", stderr.String(), sub)
				}
			}
		})
	}
}

// containsNormalizedHCLAssignment compares an HCL `key = value` substring against
// patched HCL lines while normalizing horizontal spacing around `=`.
func containsNormalizedHCLAssignment(hclText, want string) bool {
	if strings.Contains(hclText, want) {
		return true
	}
	norm := func(s string) string {
		parts := strings.Fields(s)
		return strings.Join(parts, " ")
	}
	wantNorm := norm(want)
	for _, line := range strings.Split(hclText, "\n") {
		if strings.Contains(norm(line), wantNorm) {
			return true
		}
	}
	return false
}
