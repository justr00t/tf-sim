package parser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePlanFile_AWS_Filtered(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	repoName := "payments-aws"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing AWS plan file: %v", err)
	}

	if snapshot.RepoName != repoName {
		t.Errorf("expected RepoName %q, got %q", repoName, snapshot.RepoName)
	}
	if snapshot.TerraformVer != "1.9.0" {
		t.Errorf("expected TerraformVer %q, got %q", "1.9.0", snapshot.TerraformVer)
	}
	expectedSnapshotID := "payments-aws-repo_payments_aws"
	if snapshot.SnapshotID != expectedSnapshotID {
		t.Errorf("expected SnapshotID %q, got %q", expectedSnapshotID, snapshot.SnapshotID)
	}

	// In default mode, no-op ("aws_s3_bucket.legacy_archive") and read ("data.aws_s3_bucket.existing_bucket")
	// should be filtered out, leaving exactly 2 create changes.
	if len(snapshot.ResourceChanges) != 2 {
		t.Fatalf("expected 2 resource changes after filtering no-op & read, got %d", len(snapshot.ResourceChanges))
	}

	rc0 := snapshot.ResourceChanges[0]
	if rc0.Address != "aws_s3_bucket.compliant_audit_logs" {
		t.Errorf("expected resource 0 address 'aws_s3_bucket.compliant_audit_logs', got %q", rc0.Address)
	}
	if len(rc0.Actions) != 1 || rc0.Actions[0] != "create" {
		t.Errorf("expected resource 0 actions ['create'], got %v", rc0.Actions)
	}

	rc1 := snapshot.ResourceChanges[1]
	if rc1.Address != "aws_s3_bucket.unencrypted_reports" {
		t.Errorf("expected resource 1 address 'aws_s3_bucket.unencrypted_reports', got %q", rc1.Address)
	}
	if len(rc1.Actions) != 1 || rc1.Actions[0] != "create" {
		t.Errorf("expected resource 1 actions ['create'], got %v", rc1.Actions)
	}
}

func TestParsePlanFile_AWS_IncludeNoOp(t *testing.T) {
	ctx := context.Background()
	p := NewParser(WithIncludeNoOp(true))
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	repoName := "payments-aws"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing AWS plan with includeNoOp: %v", err)
	}

	// 2 creates + 1 no-op = 3 changes (read remains filtered)
	if len(snapshot.ResourceChanges) != 3 {
		t.Fatalf("expected 3 resource changes with includeNoOp=true, got %d", len(snapshot.ResourceChanges))
	}

	var foundNoOp bool
	for _, rc := range snapshot.ResourceChanges {
		if rc.Address == "aws_s3_bucket.legacy_archive" {
			foundNoOp = true
			if len(rc.Actions) != 1 || rc.Actions[0] != "no-op" {
				t.Errorf("expected actions ['no-op'], got %v", rc.Actions)
			}
		}
	}
	if !foundNoOp {
		t.Errorf("expected 'aws_s3_bucket.legacy_archive' with action 'no-op' to be present")
	}
}

func TestParsePlanFile_AWS_IncludeRead(t *testing.T) {
	ctx := context.Background()
	p := NewParser(WithIncludeRead(true))
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	repoName := "payments-aws"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing AWS plan with includeRead: %v", err)
	}

	// 2 creates + 1 read = 3 changes (no-op remains filtered)
	if len(snapshot.ResourceChanges) != 3 {
		t.Fatalf("expected 3 resource changes with includeRead=true, got %d", len(snapshot.ResourceChanges))
	}

	var foundRead bool
	for _, rc := range snapshot.ResourceChanges {
		if rc.Address == "data.aws_s3_bucket.existing_bucket" {
			foundRead = true
			if len(rc.Actions) != 1 || rc.Actions[0] != "read" {
				t.Errorf("expected actions ['read'], got %v", rc.Actions)
			}
		}
	}
	if !foundRead {
		t.Errorf("expected 'data.aws_s3_bucket.existing_bucket' with action 'read' to be present")
	}
}

func TestParsePlanFile_AWS_IncludeAll(t *testing.T) {
	ctx := context.Background()
	p := NewParser(WithIncludeNoOp(true), WithIncludeRead(true))
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	repoName := "payments-aws"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing AWS plan with includeNoOp and includeRead: %v", err)
	}

	// All 4 changes should be present (2 create, 1 no-op, 1 read)
	if len(snapshot.ResourceChanges) != 4 {
		t.Fatalf("expected 4 resource changes with both options enabled, got %d", len(snapshot.ResourceChanges))
	}

	addresses := make(map[string]bool)
	for _, rc := range snapshot.ResourceChanges {
		addresses[rc.Address] = true
	}
	expectedAddresses := []string{
		"aws_s3_bucket.compliant_audit_logs",
		"aws_s3_bucket.unencrypted_reports",
		"aws_s3_bucket.legacy_archive",
		"data.aws_s3_bucket.existing_bucket",
	}
	for _, expected := range expectedAddresses {
		if !addresses[expected] {
			t.Errorf("expected address %q to be included", expected)
		}
	}
}

func TestParsePlanFile_Azure(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")
	repoName := "data-azure"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing Azure plan file: %v", err)
	}

	// In default mode, no-op ("azurerm_storage_account.static_assets") is filtered out.
	// Leaves 2 changes: "azurerm_storage_account.compliant_lake" (create) and
	// "azurerm_storage_account.insecure_transfer" (update).
	if len(snapshot.ResourceChanges) != 2 {
		t.Fatalf("expected 2 resource changes, got %d", len(snapshot.ResourceChanges))
	}

	rc1 := snapshot.ResourceChanges[1]
	if rc1.Address != "azurerm_storage_account.insecure_transfer" {
		t.Errorf("expected resource 1 address 'azurerm_storage_account.insecure_transfer', got %q", rc1.Address)
	}
	if len(rc1.Actions) != 1 || rc1.Actions[0] != "update" {
		t.Errorf("expected actions ['update'], got %v", rc1.Actions)
	}

	if rc1.Before == nil {
		t.Fatal("expected non-nil Before map for update change")
	}
	if enabled, ok := rc1.Before["https_traffic_only_enabled"].(bool); !ok || enabled != false {
		t.Errorf("expected Before['https_traffic_only_enabled'] == false, got %v", rc1.Before["https_traffic_only_enabled"])
	}

	if rc1.After == nil {
		t.Fatal("expected non-nil After map for update change")
	}
	if enabled, ok := rc1.After["https_traffic_only_enabled"].(bool); !ok || enabled != false {
		t.Errorf("expected After['https_traffic_only_enabled'] == false, got %v", rc1.After["https_traffic_only_enabled"])
	}
}

func TestParsePlanFile_GCP(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_ml_gcp.json")
	repoName := "ml-gcp"

	snapshot, err := p.ParsePlanFile(ctx, planPath, repoName)
	if err != nil {
		t.Fatalf("unexpected error parsing GCP plan file: %v", err)
	}

	// In default mode, read ("google_storage_bucket.checkpoint_cache") is filtered out.
	// Leaves 2 changes: "google_storage_bucket.secure_models" and "google_storage_bucket.open_training_data".
	if len(snapshot.ResourceChanges) != 2 {
		t.Fatalf("expected 2 resource changes, got %d", len(snapshot.ResourceChanges))
	}

	rc0 := snapshot.ResourceChanges[0]
	if rc0.Address != "google_storage_bucket.secure_models" {
		t.Errorf("expected resource 0 address 'google_storage_bucket.secure_models', got %q", rc0.Address)
	}
	if ubla, ok := rc0.After["uniform_bucket_level_access"].(bool); !ok || !ubla {
		t.Errorf("expected resource 0 uniform_bucket_level_access == true, got %v", rc0.After["uniform_bucket_level_access"])
	}

	rc1 := snapshot.ResourceChanges[1]
	if rc1.Address != "google_storage_bucket.open_training_data" {
		t.Errorf("expected resource 1 address 'google_storage_bucket.open_training_data', got %q", rc1.Address)
	}
	if ubla, ok := rc1.After["uniform_bucket_level_access"].(bool); !ok || ubla {
		t.Errorf("expected resource 1 uniform_bucket_level_access == false, got %v", rc1.After["uniform_bucket_level_access"])
	}
}

func TestParsePlanReader_EmptyChanges(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	input := `{"terraform_version":"1.8.0","resource_changes":[]}`

	snapshot, err := p.ParsePlanReader(ctx, strings.NewReader(input), "test-repo", "plan.json")
	if err != nil {
		t.Fatalf("unexpected error parsing plan with empty resource_changes: %v", err)
	}

	if snapshot.TerraformVer != "1.8.0" {
		t.Errorf("expected TerraformVer '1.8.0', got %q", snapshot.TerraformVer)
	}
	if snapshot.ResourceChanges == nil {
		t.Error("expected snapshot.ResourceChanges to be non-nil empty slice")
	}
	if len(snapshot.ResourceChanges) != 0 {
		t.Errorf("expected 0 resource changes, got %d", len(snapshot.ResourceChanges))
	}
}

func TestParsePlanReader_MissingChangesKey(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	input := `{"terraform_version":"1.8.0"}`

	snapshot, err := p.ParsePlanReader(ctx, strings.NewReader(input), "test-repo", "plan.json")
	if err != nil {
		t.Fatalf("unexpected error parsing plan without resource_changes key: %v", err)
	}

	if snapshot.TerraformVer != "1.8.0" {
		t.Errorf("expected TerraformVer '1.8.0', got %q", snapshot.TerraformVer)
	}
	if snapshot.ResourceChanges == nil {
		t.Error("expected snapshot.ResourceChanges to be non-nil empty slice")
	}
	if len(snapshot.ResourceChanges) != 0 {
		t.Errorf("expected 0 resource changes, got %d", len(snapshot.ResourceChanges))
	}
}

func TestParsePlanReader_LargeSiblingSkips(t *testing.T) {
	ctx := context.Background()
	p := NewParser()

	// Plan contains large nested blobs in prior_state and configuration
	// surrounding terraform_version and resource_changes
	input := `{
		"format_version": "1.2",
		"prior_state": {
			"deep": {
				"nested": [1, 2, 3, {"extra": "nested_blob", "arr": [true, false, null]}],
				"more": {"a": "b", "c": [10, 20, 30]}
			}
		},
		"terraform_version": "1.9.0",
		"configuration": {
			"root_module": {
				"resources": [
					{"type": "aws_vpc", "name": "main", "values": {"cidr": "10.0.0.0/16"}}
				]
			}
		},
		"resource_changes": [
			{
				"address": "aws_s3_bucket.streamed",
				"type": "aws_s3_bucket",
				"name": "streamed",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"after": {
						"bucket": "streamed-bucket"
					}
				}
			}
		],
		"planned_values": {
			"root_module": {
				"resources": []
			}
		}
	}`

	snapshot, err := p.ParsePlanReader(ctx, strings.NewReader(input), "large-repo", "large.json")
	if err != nil {
		t.Fatalf("unexpected error skipping large sibling blobs: %v", err)
	}

	if snapshot.TerraformVer != "1.9.0" {
		t.Errorf("expected TerraformVer '1.9.0', got %q", snapshot.TerraformVer)
	}
	if len(snapshot.ResourceChanges) != 1 {
		t.Fatalf("expected 1 resource change, got %d", len(snapshot.ResourceChanges))
	}
	if snapshot.ResourceChanges[0].Address != "aws_s3_bucket.streamed" {
		t.Errorf("expected address 'aws_s3_bucket.streamed', got %q", snapshot.ResourceChanges[0].Address)
	}
	if bucket, ok := snapshot.ResourceChanges[0].After["bucket"].(string); !ok || bucket != "streamed-bucket" {
		t.Errorf("expected bucket 'streamed-bucket', got %v", snapshot.ResourceChanges[0].After["bucket"])
	}
}

func TestParsePlanFile_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately

	p := NewParser()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

	_, err := p.ParsePlanFile(ctx, planPath, "payments-aws")
	if err == nil {
		t.Fatal("expected error with canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled), got: %v", err)
	}
}

func TestParsePlanFile_FileNotFound(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	nonExistentPath := filepath.Join("..", "..", "testdata", "plans", "nonexistent.json")

	_, err := p.ParsePlanFile(ctx, nonExistentPath, "test-repo")
	if err == nil {
		t.Fatal("expected error for non-existent plan file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "stat plan file") {
		t.Errorf("expected ErrNotExist or wrapped stat error, got: %v", err)
	}
}

func TestParsePlanFile_DirectoryPath(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	dirPath := filepath.Join("..", "..", "testdata", "plans")

	_, err := p.ParsePlanFile(ctx, dirPath, "test-repo")
	if err == nil {
		t.Fatal("expected error when passing directory path, got nil")
	}
	if !strings.Contains(err.Error(), "is a directory, not a file") {
		t.Errorf("expected error message to contain 'is a directory, not a file', got: %v", err)
	}
}

func TestParsePlanReader_MalformedJSON(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	malformed := `{"resource_changes": [{"address": "broken"`

	_, err := p.ParsePlanReader(ctx, strings.NewReader(malformed), "test-repo", "broken.json")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParsePlanReader_NonObjectRoot(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	nonObject := `["array", "root"]`

	_, err := p.ParsePlanReader(ctx, strings.NewReader(nonObject), "test-repo", "array.json")
	if err == nil {
		t.Fatal("expected error for non-object JSON root, got nil")
	}
}
