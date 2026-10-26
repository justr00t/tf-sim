package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
)

func TestEvaluatePlan_AWS_S3Encryption(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	snapshot, err := p.ParsePlanFile(ctx, planPath, "repo-payments-aws")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	eval := engine.NewEvaluator()

	res, err := eval.EvaluatePlan(ctx, []string{policyPath}, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan returned unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil EvalResult")
	}

	if res.Passed {
		t.Errorf("expected Passed == false, got true")
	}
	if res.TotalResources != 2 {
		t.Errorf("expected TotalResources == 2, got %d", res.TotalResources)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected exactly 1 violation, got %d: %+v", len(res.Violations), res.Violations)
	}

	v := res.Violations[0]
	if v.ResourceAddress != "aws_s3_bucket.unencrypted_reports" {
		t.Errorf("expected ResourceAddress == 'aws_s3_bucket.unencrypted_reports', got %q", v.ResourceAddress)
	}
	if v.RuleID != "AWS-S3-ENCRYPT-001" {
		t.Errorf("expected RuleID == 'AWS-S3-ENCRYPT-001', got %q", v.RuleID)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected Severity == 'HIGH', got %q", v.Severity)
	}
	if v.Remediation == nil {
		t.Fatal("expected non-nil Remediation")
	}

	expectedPath := []string{
		"server_side_encryption_configuration",
		"rule",
		"apply_server_side_encryption_by_default",
		"sse_algorithm",
	}
	if !reflect.DeepEqual(v.Remediation.AttributePath, expectedPath) {
		t.Errorf("expected Remediation.AttributePath %v, got %v", expectedPath, v.Remediation.AttributePath)
	}
	if v.Remediation.SuggestedVal != "aws:kms" {
		t.Errorf("expected SuggestedVal == 'aws:kms', got %v", v.Remediation.SuggestedVal)
	}
}

func TestEvaluatePlan_Azure_StorageHTTPS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	snapshot, err := p.ParsePlanFile(ctx, planPath, "repo-data-azure")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	eval := engine.NewEvaluator()

	res, err := eval.EvaluatePlan(ctx, []string{policyPath}, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan returned unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil EvalResult")
	}

	if res.Passed {
		t.Errorf("expected Passed == false, got true")
	}
	if res.TotalResources != 2 {
		t.Errorf("expected TotalResources == 2, got %d", res.TotalResources)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected exactly 1 violation, got %d: %+v", len(res.Violations), res.Violations)
	}

	v := res.Violations[0]
	if v.ResourceAddress != "azurerm_storage_account.insecure_transfer" {
		t.Errorf("expected ResourceAddress == 'azurerm_storage_account.insecure_transfer', got %q", v.ResourceAddress)
	}
	if v.RuleID != "AZURE-STORAGE-HTTPS-001" {
		t.Errorf("expected RuleID == 'AZURE-STORAGE-HTTPS-001', got %q", v.RuleID)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected Severity == 'HIGH', got %q", v.Severity)
	}
	if v.Remediation == nil {
		t.Fatal("expected non-nil Remediation")
	}

	expectedPath := []string{"https_traffic_only_enabled"}
	if !reflect.DeepEqual(v.Remediation.AttributePath, expectedPath) {
		t.Errorf("expected Remediation.AttributePath %v, got %v", expectedPath, v.Remediation.AttributePath)
	}
	if v.Remediation.SuggestedVal != true {
		t.Errorf("expected SuggestedVal == true, got %v", v.Remediation.SuggestedVal)
	}
}

func TestEvaluatePlan_GCP_StorageUBLA(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_ml_gcp.json")
	snapshot, err := p.ParsePlanFile(ctx, planPath, "repo-ml-gcp")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	eval := engine.NewEvaluator()

	res, err := eval.EvaluatePlan(ctx, []string{policyPath}, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan returned unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil EvalResult")
	}

	if res.Passed {
		t.Errorf("expected Passed == false, got true")
	}
	if res.TotalResources != 2 {
		t.Errorf("expected TotalResources == 2, got %d", res.TotalResources)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected exactly 1 violation, got %d: %+v", len(res.Violations), res.Violations)
	}

	v := res.Violations[0]
	if v.ResourceAddress != "google_storage_bucket.open_training_data" {
		t.Errorf("expected ResourceAddress == 'google_storage_bucket.open_training_data', got %q", v.ResourceAddress)
	}
	if v.RuleID != "GCP-STORAGE-UBLA-001" {
		t.Errorf("expected RuleID == 'GCP-STORAGE-UBLA-001', got %q", v.RuleID)
	}
	if v.Severity != "MEDIUM" {
		t.Errorf("expected Severity == 'MEDIUM', got %q", v.Severity)
	}
	if v.Remediation == nil {
		t.Fatal("expected non-nil Remediation")
	}

	expectedPath := []string{"uniform_bucket_level_access"}
	if !reflect.DeepEqual(v.Remediation.AttributePath, expectedPath) {
		t.Errorf("expected Remediation.AttributePath %v, got %v", expectedPath, v.Remediation.AttributePath)
	}
	if v.Remediation.SuggestedVal != true {
		t.Errorf("expected SuggestedVal == true, got %v", v.Remediation.SuggestedVal)
	}
}

func TestEvaluatePlan_DualEnvelopeCompatibility(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	snapshot, err := p.ParsePlanFile(ctx, planPath, "repo-data-azure")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	tmpDir := t.TempDir()

	// Direct model style: rc.after.https_traffic_only_enabled
	directPolicyContent := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.after.https_traffic_only_enabled == false
	violation := {
		"rule_id": "AZURE-DIRECT-001",
		"severity": "HIGH",
		"message": sprintf("Direct model style flag: %s", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	directPolicyPath := filepath.Join(tmpDir, "direct_style.rego")
	if err := os.WriteFile(directPolicyPath, []byte(directPolicyContent), 0644); err != nil {
		t.Fatalf("failed to write direct policy: %v", err)
	}

	// Change envelope style: rc.change.after.https_traffic_only_enabled
	changePolicyContent := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.https_traffic_only_enabled == false
	violation := {
		"rule_id": "AZURE-CHANGE-001",
		"severity": "HIGH",
		"message": sprintf("Change envelope style flag: %s", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	changePolicyPath := filepath.Join(tmpDir, "change_style.rego")
	if err := os.WriteFile(changePolicyPath, []byte(changePolicyContent), 0644); err != nil {
		t.Fatalf("failed to write change policy: %v", err)
	}

	eval := engine.NewEvaluator()

	// Evaluate direct model style
	resDirect, err := eval.EvaluatePlan(ctx, []string{directPolicyPath}, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan (direct style) failed: %v", err)
	}
	if len(resDirect.Violations) != 1 {
		t.Fatalf("expected 1 violation in direct style, got %d", len(resDirect.Violations))
	}
	if resDirect.Violations[0].ResourceAddress != "azurerm_storage_account.insecure_transfer" {
		t.Errorf("expected direct style violation on insecure_transfer, got %s", resDirect.Violations[0].ResourceAddress)
	}

	// Evaluate change envelope style
	resChange, err := eval.EvaluatePlan(ctx, []string{changePolicyPath}, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan (change style) failed: %v", err)
	}
	if len(resChange.Violations) != 1 {
		t.Fatalf("expected 1 violation in change style, got %d", len(resChange.Violations))
	}
	if resChange.Violations[0].ResourceAddress != "azurerm_storage_account.insecure_transfer" {
		t.Errorf("expected change style violation on insecure_transfer, got %s", resChange.Violations[0].ResourceAddress)
	}
}

func TestEvaluatePlan_CleanPassingSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	cleanSnapshot := &model.PlanSnapshot{
		SnapshotID:   "snap-clean-01",
		RepoName:     "clean-repo",
		TerraformVer: "1.9.0",
		SourcePath:   "testdata/clean.json",
		ResourceChanges: []model.ResourceChange{
			{
				Address:      "aws_s3_bucket.compliant_audit_logs",
				Type:         "aws_s3_bucket",
				Name:         "compliant_audit_logs",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Actions:      []string{"create"},
				After: map[string]any{
					"bucket": "company-audit-logs",
					"server_side_encryption_configuration": []any{
						map[string]any{
							"rule": []any{
								map[string]any{
									"apply_server_side_encryption_by_default": []any{
										map[string]any{
											"kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/123",
											"sse_algorithm":     "aws:kms",
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Address:      "azurerm_storage_account.compliant_lake",
				Type:         "azurerm_storage_account",
				Name:         "compliant_lake",
				ProviderName: "registry.terraform.io/hashicorp/azurerm",
				Actions:      []string{"create"},
				After: map[string]any{
					"account_replication_type":   "GRS",
					"account_tier":               "Standard",
					"https_traffic_only_enabled": true,
					"name":                       "datalakeprod",
				},
			},
		},
	}

	eval := engine.NewEvaluator()
	res, err := eval.EvaluatePlan(ctx, []string{policyPath}, cleanSnapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan failed: %v", err)
	}
	if !res.Passed {
		t.Errorf("expected Passed == true for clean snapshot, got false with violations: %+v", res.Violations)
	}
	if len(res.Violations) != 0 {
		t.Errorf("expected 0 violations for clean snapshot, got %d", len(res.Violations))
	}
	if res.TotalResources != 2 {
		t.Errorf("expected TotalResources == 2, got %d", res.TotalResources)
	}
}

func TestEvaluatePlan_DeterministicSorting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	// Create snapshot with resources intentionally out of alphabetical order
	shuffledSnapshot := &model.PlanSnapshot{
		SnapshotID:   "snap-shuffled-01",
		RepoName:     "multi-cloud-repo",
		TerraformVer: "1.9.0",
		SourcePath:   "testdata/shuffled.json",
		ResourceChanges: []model.ResourceChange{
			{
				Address:      "google_storage_bucket.open_training_data",
				Type:         "google_storage_bucket",
				Name:         "open_training_data",
				ProviderName: "registry.terraform.io/hashicorp/google",
				Actions:      []string{"create"},
				After: map[string]any{
					"name":                        "ml-training-raw",
					"uniform_bucket_level_access": false,
				},
			},
			{
				Address:      "azurerm_storage_account.insecure_transfer",
				Type:         "azurerm_storage_account",
				Name:         "insecure_transfer",
				ProviderName: "registry.terraform.io/hashicorp/azurerm",
				Actions:      []string{"create"},
				After: map[string]any{
					"name":                       "insecuretransfer",
					"https_traffic_only_enabled": false,
				},
			},
			{
				Address:      "aws_s3_bucket.unencrypted_reports",
				Type:         "aws_s3_bucket",
				Name:         "unencrypted_reports",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Actions:      []string{"create"},
				After: map[string]any{
					"bucket": "company-unencrypted-reports",
				},
			},
		},
	}

	eval := engine.NewEvaluator()
	res, err := eval.EvaluatePlan(ctx, []string{policyPath}, shuffledSnapshot)
	if err != nil {
		t.Fatalf("EvaluatePlan failed: %v", err)
	}
	if res.Passed {
		t.Fatalf("expected Passed == false, got true")
	}
	if len(res.Violations) != 3 {
		t.Fatalf("expected 3 violations, got %d: %+v", len(res.Violations), res.Violations)
	}

	// Verify strictly sorted: aws < azurerm < google
	expectedAddresses := []string{
		"aws_s3_bucket.unencrypted_reports",
		"azurerm_storage_account.insecure_transfer",
		"google_storage_bucket.open_training_data",
	}

	for i, expected := range expectedAddresses {
		if res.Violations[i].ResourceAddress != expected {
			t.Errorf("violation[%d] expected address %q, got %q", i, expected, res.Violations[i].ResourceAddress)
		}
	}
}

func TestEvaluatePlan_NilSnapshotError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	eval := engine.NewEvaluator()

	_, err := eval.EvaluatePlan(ctx, []string{policyPath}, nil)
	if err == nil {
		t.Fatal("expected error with nil snapshot, got nil")
	}
	if !strings.Contains(err.Error(), "plan snapshot cannot be nil") {
		t.Errorf("expected error message to contain 'plan snapshot cannot be nil', got %q", err.Error())
	}
}

func TestEvaluatePlan_EmptyPoliciesError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	snapshot, err := p.ParsePlanFile(ctx, planPath, "repo-data-azure")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	eval := engine.NewEvaluator()
	_, err = eval.EvaluatePlan(ctx, []string{}, snapshot)
	if err == nil {
		t.Fatal("expected error with empty policyPaths, got nil")
	}
	if !strings.Contains(err.Error(), "at least one policy path must be provided") {
		t.Errorf("expected error message to contain 'at least one policy path must be provided', got %q", err.Error())
	}
}

func TestEvaluatePlan_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := parser.NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	snapshot, err := p.ParsePlanFile(context.Background(), planPath, "repo-data-azure")
	if err != nil {
		t.Fatalf("ParsePlanFile failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	eval := engine.NewEvaluator()

	_, err = eval.EvaluatePlan(ctx, []string{policyPath}, snapshot)
	if err == nil {
		t.Fatal("expected error with cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to be context.Canceled, got %v", err)
	}
}
