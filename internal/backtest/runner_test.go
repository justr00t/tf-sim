package backtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boomer/tf-sim/internal/engine"
	"github.com/boomer/tf-sim/internal/model"
	"github.com/boomer/tf-sim/internal/parser"
)

// TestNewRunner_Defaults verifies that NewRunner initializes with production defaults.
func TestNewRunner_Defaults(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("expected non-nil Runner")
	}
	if r.evaluator == nil {
		t.Error("expected default evaluator to be non-nil")
	}
	if r.parser == nil {
		t.Error("expected default parser to be non-nil")
	}
	if r.concurrency < 1 {
		t.Errorf("expected concurrency >= 1, got %d", r.concurrency)
	}
}

// TestNewRunner_WithOptions verifies functional option injection and concurrency clamping.
func TestNewRunner_WithOptions(t *testing.T) {
	customEval := engine.NewEvaluator()
	customParser := parser.NewParser()

	r := NewRunner(
		WithEvaluator(customEval),
		WithParser(customParser),
		WithConcurrency(4),
	)
	if r.evaluator != customEval {
		t.Error("expected custom evaluator to be configured")
	}
	if r.parser != customParser {
		t.Error("expected custom parser to be configured")
	}
	if r.concurrency != 4 {
		t.Errorf("expected concurrency 4, got %d", r.concurrency)
	}

	// Concurrency clamping
	rClamped := NewRunner(WithConcurrency(-5))
	if rClamped.concurrency != 1 {
		t.Errorf("expected clamped concurrency 1 for negative input, got %d", rClamped.concurrency)
	}

	rZero := NewRunner(WithConcurrency(0))
	if rZero.concurrency != 1 {
		t.Errorf("expected clamped concurrency 1 for zero input, got %d", rZero.concurrency)
	}
}

// TestRunBacktest_MultiCloudCorpus executes an integration backtest across AWS, Azure, and GCP snapshots.
func TestRunBacktest_MultiCloudCorpus(t *testing.T) {
	ctx := context.Background()
	p := parser.NewParser()

	awsPlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	azurePlan := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	gcpPlan := filepath.Join("..", "..", "testdata", "plans", "repo_ml_gcp.json")
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	snapAWS, err := p.ParsePlanFile(ctx, awsPlan, "repo-payments-aws")
	if err != nil {
		t.Fatalf("failed to parse AWS plan: %v", err)
	}
	snapAzure, err := p.ParsePlanFile(ctx, azurePlan, "repo-data-azure")
	if err != nil {
		t.Fatalf("failed to parse Azure plan: %v", err)
	}
	snapGCP, err := p.ParsePlanFile(ctx, gcpPlan, "repo-ml-gcp")
	if err != nil {
		t.Fatalf("failed to parse GCP plan: %v", err)
	}

	runner := NewRunner()
	report, err := runner.RunBacktest(ctx, []string{policyPath}, []*model.PlanSnapshot{snapAWS, snapAzure, snapGCP})
	if err != nil {
		t.Fatalf("RunBacktest failed: %v", err)
	}

	if report.TotalReposAnalyzed != 3 {
		t.Errorf("expected TotalReposAnalyzed=3, got %d", report.TotalReposAnalyzed)
	}
	if report.ImpactedReposCount != 3 {
		t.Errorf("expected ImpactedReposCount=3, got %d", report.ImpactedReposCount)
	}
	if report.TotalPlansAnalyzed != 3 {
		t.Errorf("expected TotalPlansAnalyzed=3, got %d", report.TotalPlansAnalyzed)
	}
	if report.BlockedPlansCount != 3 {
		t.Errorf("expected BlockedPlansCount=3, got %d", report.BlockedPlansCount)
	}
	if report.TotalResources != 6 {
		t.Errorf("expected TotalResources=6, got %d", report.TotalResources)
	}
	if report.TotalViolations != 3 {
		t.Errorf("expected TotalViolations=3, got %d", report.TotalViolations)
	}

	expectedBreakdown := map[string]int{
		"aws":     1,
		"azurerm": 1,
		"google":  1,
	}
	for prov, count := range expectedBreakdown {
		if report.BreakdownByProvider[prov] != count {
			t.Errorf("expected BreakdownByProvider[%q]=%d, got %d", prov, count, report.BreakdownByProvider[prov])
		}
	}

	if len(report.RepoImpacts) != 3 {
		t.Fatalf("expected 3 RepoImpacts, got %d", len(report.RepoImpacts))
	}

	expectedRepos := []string{"repo-data-azure", "repo-ml-gcp", "repo-payments-aws"}
	for i, expected := range expectedRepos {
		if report.RepoImpacts[i].RepoName != expected {
			t.Errorf("expected RepoImpacts[%d].RepoName=%q, got %q", i, expected, report.RepoImpacts[i].RepoName)
		}
	}

	// Azure verification: 1 violation AZURE-STORAGE-HTTPS-001 on azurerm_storage_account.insecure_transfer
	azureImpact := report.RepoImpacts[0]
	if len(azureImpact.Violations) != 1 {
		t.Fatalf("expected 1 violation in repo-data-azure, got %d", len(azureImpact.Violations))
	}
	if azureImpact.Violations[0].RuleID != "AZURE-STORAGE-HTTPS-001" {
		t.Errorf("expected AZURE-STORAGE-HTTPS-001, got %s", azureImpact.Violations[0].RuleID)
	}
	if azureImpact.Violations[0].ResourceAddress != "azurerm_storage_account.insecure_transfer" {
		t.Errorf("expected azurerm_storage_account.insecure_transfer, got %s", azureImpact.Violations[0].ResourceAddress)
	}

	// GCP verification: 1 violation GCP-STORAGE-UBLA-001 on google_storage_bucket.open_training_data
	gcpImpact := report.RepoImpacts[1]
	if len(gcpImpact.Violations) != 1 {
		t.Fatalf("expected 1 violation in repo-ml-gcp, got %d", len(gcpImpact.Violations))
	}
	if gcpImpact.Violations[0].RuleID != "GCP-STORAGE-UBLA-001" {
		t.Errorf("expected GCP-STORAGE-UBLA-001, got %s", gcpImpact.Violations[0].RuleID)
	}
	if gcpImpact.Violations[0].ResourceAddress != "google_storage_bucket.open_training_data" {
		t.Errorf("expected google_storage_bucket.open_training_data, got %s", gcpImpact.Violations[0].ResourceAddress)
	}

	// AWS verification: 1 violation AWS-S3-ENCRYPT-001 on aws_s3_bucket.unencrypted_reports
	awsImpact := report.RepoImpacts[2]
	if len(awsImpact.Violations) != 1 {
		t.Fatalf("expected 1 violation in repo-payments-aws, got %d", len(awsImpact.Violations))
	}
	if awsImpact.Violations[0].RuleID != "AWS-S3-ENCRYPT-001" {
		t.Errorf("expected AWS-S3-ENCRYPT-001, got %s", awsImpact.Violations[0].RuleID)
	}
	if awsImpact.Violations[0].ResourceAddress != "aws_s3_bucket.unencrypted_reports" {
		t.Errorf("expected aws_s3_bucket.unencrypted_reports, got %s", awsImpact.Violations[0].ResourceAddress)
	}
}

// TestRunBacktest_MultiSnapshotsPerRepo verifies aggregation of multiple historical snapshots for a single repo.
func TestRunBacktest_MultiSnapshotsPerRepo(t *testing.T) {
	ctx := context.Background()
	p := parser.NewParser()
	awsPlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	snapAWS, err := p.ParsePlanFile(ctx, awsPlan, "repo-payments-aws")
	if err != nil {
		t.Fatalf("failed to parse AWS plan: %v", err)
	}
	if len(snapAWS.ResourceChanges) < 2 {
		t.Fatalf("expected at least 2 resource changes in AWS plan, got %d", len(snapAWS.ResourceChanges))
	}

	snapCompliant := &model.PlanSnapshot{
		SnapshotID:      "snap-compliant",
		RepoName:        "repo-payments-aws",
		ResourceChanges: []model.ResourceChange{snapAWS.ResourceChanges[0]},
	}
	snapViolating := &model.PlanSnapshot{
		SnapshotID:      "snap-violating",
		RepoName:        "repo-payments-aws",
		ResourceChanges: []model.ResourceChange{snapAWS.ResourceChanges[1]},
	}

	runner := NewRunner()
	report, err := runner.RunBacktest(ctx, []string{policyPath}, []*model.PlanSnapshot{snapCompliant, snapViolating})
	if err != nil {
		t.Fatalf("RunBacktest failed: %v", err)
	}

	if report.TotalReposAnalyzed != 1 {
		t.Errorf("expected TotalReposAnalyzed=1, got %d", report.TotalReposAnalyzed)
	}
	if report.ImpactedReposCount != 1 {
		t.Errorf("expected ImpactedReposCount=1, got %d", report.ImpactedReposCount)
	}
	if report.TotalPlansAnalyzed != 2 {
		t.Errorf("expected TotalPlansAnalyzed=2, got %d", report.TotalPlansAnalyzed)
	}
	if report.BlockedPlansCount != 1 {
		t.Errorf("expected BlockedPlansCount=1, got %d", report.BlockedPlansCount)
	}
	if len(report.RepoImpacts) != 1 {
		t.Fatalf("expected 1 RepoImpact, got %d", len(report.RepoImpacts))
	}
	impact := report.RepoImpacts[0]
	if impact.TotalPlansTested != 2 {
		t.Errorf("expected TotalPlansTested=2, got %d", impact.TotalPlansTested)
	}
	if impact.BlockedPlansCount != 1 {
		t.Errorf("expected BlockedPlansCount=1, got %d", impact.BlockedPlansCount)
	}
	if len(impact.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(impact.Violations))
	}
}

// TestRunBacktest_CleanPassingBacktest verifies zero false positives for fully compliant snapshots.
func TestRunBacktest_CleanPassingBacktest(t *testing.T) {
	ctx := context.Background()
	p := parser.NewParser()
	awsPlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	snapAWS, err := p.ParsePlanFile(ctx, awsPlan, "repo-clean-aws")
	if err != nil {
		t.Fatalf("failed to parse AWS plan: %v", err)
	}

	snapClean := &model.PlanSnapshot{
		SnapshotID:      "snap-clean",
		RepoName:        "repo-clean-aws",
		ResourceChanges: []model.ResourceChange{snapAWS.ResourceChanges[0]}, // compliant bucket
	}

	runner := NewRunner()
	report, err := runner.RunBacktest(ctx, []string{policyPath}, []*model.PlanSnapshot{snapClean})
	if err != nil {
		t.Fatalf("RunBacktest failed: %v", err)
	}

	if report.ImpactedReposCount != 0 {
		t.Errorf("expected ImpactedReposCount=0, got %d", report.ImpactedReposCount)
	}
	if report.BlockedPlansCount != 0 {
		t.Errorf("expected BlockedPlansCount=0, got %d", report.BlockedPlansCount)
	}
	if report.TotalViolations != 0 {
		t.Errorf("expected TotalViolations=0, got %d", report.TotalViolations)
	}
	if len(report.BreakdownByProvider) != 0 {
		t.Errorf("expected empty BreakdownByProvider, got %v", report.BreakdownByProvider)
	}
	if len(report.RepoImpacts) != 1 {
		t.Fatalf("expected 1 RepoImpact, got %d", len(report.RepoImpacts))
	}
	if report.RepoImpacts[0].BlockedPlansCount != 0 {
		t.Errorf("expected BlockedPlansCount=0, got %d", report.RepoImpacts[0].BlockedPlansCount)
	}
	if len(report.RepoImpacts[0].Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(report.RepoImpacts[0].Violations))
	}
}

// TestExtractProviderName validates cloud-agnostic provider identification across various inputs.
func TestExtractProviderName(t *testing.T) {
	tests := []struct {
		rcProviderName string
		resourceType   string
		expected       string
	}{
		{"registry.terraform.io/hashicorp/aws", "aws_s3_bucket", "aws"},
		{"hashicorp/azurerm", "azurerm_storage_account", "azurerm"},
		{"google", "google_storage_bucket", "google"},
		{"", "google_storage_bucket", "google"},
		{"", "kubernetes_pod", "kubernetes"},
		{"", "random_string", "random"},
		{"", "simple", "unknown"},
		{"", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.rcProviderName, tt.resourceType), func(t *testing.T) {
			got := ExtractProviderName(tt.rcProviderName, tt.resourceType)
			if got != tt.expected {
				t.Errorf("ExtractProviderName(%q, %q) = %q, expected %q", tt.rcProviderName, tt.resourceType, got, tt.expected)
			}
		})
	}
}

// TestRunBacktest_EmptySnapshots validates graceful zeroed report generation when snapshot list is empty.
func TestRunBacktest_EmptySnapshots(t *testing.T) {
	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	runner := NewRunner()
	report, err := runner.RunBacktest(ctx, []string{policyPath}, []*model.PlanSnapshot{})
	if err != nil {
		t.Fatalf("expected nil error for empty snapshots, got: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report for empty snapshots")
	}
	if report.TotalReposAnalyzed != 0 {
		t.Errorf("expected TotalReposAnalyzed=0, got %d", report.TotalReposAnalyzed)
	}
	if report.ImpactedReposCount != 0 {
		t.Errorf("expected ImpactedReposCount=0, got %d", report.ImpactedReposCount)
	}
	if report.TotalPlansAnalyzed != 0 {
		t.Errorf("expected TotalPlansAnalyzed=0, got %d", report.TotalPlansAnalyzed)
	}
	if report.BlockedPlansCount != 0 {
		t.Errorf("expected BlockedPlansCount=0, got %d", report.BlockedPlansCount)
	}
	if report.TotalResources != 0 {
		t.Errorf("expected TotalResources=0, got %d", report.TotalResources)
	}
	if report.TotalViolations != 0 {
		t.Errorf("expected TotalViolations=0, got %d", report.TotalViolations)
	}
	if report.BreakdownByProvider == nil {
		t.Error("expected non-nil BreakdownByProvider map")
	}
	if report.RepoImpacts == nil {
		t.Error("expected non-nil RepoImpacts slice")
	}
}

// TestRunBacktest_ValidationErrors verifies descriptive input validation error handling.
func TestRunBacktest_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	runner := NewRunner()

	// Empty policy paths
	_, err := runner.RunBacktest(ctx, []string{}, []*model.PlanSnapshot{})
	if err == nil {
		t.Error("expected error for empty policyPaths, got nil")
	} else if !strings.Contains(err.Error(), "policy path") {
		t.Errorf("expected error mentioning 'policy path', got: %v", err)
	}

	// Slice with nil snapshot element
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	_, err = runner.RunBacktest(ctx, []string{policyPath}, []*model.PlanSnapshot{nil})
	if err == nil {
		t.Error("expected error for nil snapshot element, got nil")
	} else if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error mentioning 'nil', got: %v", err)
	}
}

// TestRunBacktest_ContextCancellation verifies that cancellation halts processing and returns context errors.
func TestRunBacktest_ContextCancellation(t *testing.T) {
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	runner := NewRunner()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	snap := &model.PlanSnapshot{
		SnapshotID: "snap-1",
		RepoName:   "repo-test",
	}
	_, err := runner.RunBacktest(canceledCtx, []string{policyPath}, []*model.PlanSnapshot{snap})
	if err == nil {
		t.Fatal("expected error with pre-canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestRunBacktest_ConcurrencyStress validates thread safety and deterministic byte-for-byte output under concurrent load.
func TestRunBacktest_ConcurrencyStress(t *testing.T) {
	ctx := context.Background()
	p := parser.NewParser()
	awsPlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")

	baseSnap, err := p.ParsePlanFile(ctx, awsPlan, "repo-payments-aws")
	if err != nil {
		t.Fatalf("failed to parse AWS plan: %v", err)
	}

	var snapshots []*model.PlanSnapshot
	repoNames := []string{"repo-1", "repo-2", "repo-3", "repo-4", "repo-5", "repo-6"}
	for i := 0; i < 30; i++ {
		repo := repoNames[i%len(repoNames)]
		var rcs []model.ResourceChange
		if i%2 == 0 {
			rcs = []model.ResourceChange{baseSnap.ResourceChanges[0]} // compliant
		} else {
			rcs = []model.ResourceChange{baseSnap.ResourceChanges[1]} // violating
		}
		snapshots = append(snapshots, &model.PlanSnapshot{
			SnapshotID:      fmt.Sprintf("snap-%d", i),
			RepoName:        repo,
			ResourceChanges: rcs,
		})
	}

	runner := NewRunner(WithConcurrency(4))

	var firstJSON []byte
	for run := 0; run < 5; run++ {
		report, err := runner.RunBacktest(ctx, []string{policyPath}, snapshots)
		if err != nil {
			t.Fatalf("run %d failed: %v", run, err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("failed to marshal report in run %d: %v", run, err)
		}
		if run == 0 {
			firstJSON = data
		} else {
			if string(data) != string(firstJSON) {
				t.Fatalf("run %d produced non-deterministic output compared to run 0", run)
			}
		}
	}
}

// TestLoadSnapshotsFromDir_HappyPath tests recursive directory loading and flat filename repo inference.
func TestLoadSnapshotsFromDir_HappyPath(t *testing.T) {
	ctx := context.Background()
	runner := NewRunner()

	plansDir := filepath.Join("..", "..", "testdata", "plans")
	snapshots, err := runner.LoadSnapshotsFromDir(ctx, plansDir)
	if err != nil {
		t.Fatalf("LoadSnapshotsFromDir failed: %v", err)
	}

	if len(snapshots) != 3 {
		t.Fatalf("expected 3 snapshots loaded, got %d", len(snapshots))
	}

	expectedRepos := []string{"repo_data_azure", "repo_ml_gcp", "repo_payments_aws"}
	for i, expected := range expectedRepos {
		if snapshots[i].RepoName != expected {
			t.Errorf("snapshots[%d].RepoName = %q, expected %q", i, snapshots[i].RepoName, expected)
		}
	}
}

// TestLoadSnapshotsFromDir_NestedSubdirectories tests repo name inference from nested subdirectory names.
func TestLoadSnapshotsFromDir_NestedSubdirectories(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	origPlanPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	planData, err := os.ReadFile(origPlanPath)
	if err != nil {
		t.Fatalf("failed to read test plan: %v", err)
	}

	repoADir := filepath.Join(tempDir, "repo-a")
	repoBDir := filepath.Join(tempDir, "repo-b")
	if err := os.MkdirAll(repoADir, 0755); err != nil {
		t.Fatalf("failed to create repo-a dir: %v", err)
	}
	if err := os.MkdirAll(repoBDir, 0755); err != nil {
		t.Fatalf("failed to create repo-b dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(repoADir, "plan1.json"), planData, 0644); err != nil {
		t.Fatalf("failed to write plan1.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoBDir, "plan2.json"), planData, 0644); err != nil {
		t.Fatalf("failed to write plan2.json: %v", err)
	}

	runner := NewRunner()
	snapshots, err := runner.LoadSnapshotsFromDir(ctx, tempDir)
	if err != nil {
		t.Fatalf("LoadSnapshotsFromDir failed: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	if snapshots[0].RepoName != "repo-a" {
		t.Errorf("snapshots[0].RepoName = %q, expected repo-a", snapshots[0].RepoName)
	}
	if snapshots[1].RepoName != "repo-b" {
		t.Errorf("snapshots[1].RepoName = %q, expected repo-b", snapshots[1].RepoName)
	}
}

// TestLoadSnapshotsFromDir_Errors tests error cases for non-existent paths, files, and canceled contexts.
func TestLoadSnapshotsFromDir_Errors(t *testing.T) {
	ctx := context.Background()
	runner := NewRunner()

	// Non-existent directory
	_, err := runner.LoadSnapshotsFromDir(ctx, filepath.Join("non", "existent", "dir"))
	if err == nil {
		t.Error("expected error for non-existent directory, got nil")
	}

	// Path is a regular file
	filePlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	_, err = runner.LoadSnapshotsFromDir(ctx, filePlan)
	if err == nil {
		t.Error("expected error for file path, got nil")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected error mentioning 'not a directory', got: %v", err)
	}

	// Canceled context
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	plansDir := filepath.Join("..", "..", "testdata", "plans")
	_, err = runner.LoadSnapshotsFromDir(canceledCtx, plansDir)
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}
