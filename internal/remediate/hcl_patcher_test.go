package remediate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// TestGeneratePatches_MultiCloudFixtures verifies surgical HCL AST remediation across AWS, Azure, and GCP fixtures.
func TestGeneratePatches_MultiCloudFixtures(t *testing.T) {
	ctx := context.Background()
	patcher := NewPatcher()

	tests := []struct {
		name              string
		tfDir             string
		violation         model.PolicyViolation
		wantResourceAddr  string
		wantPatchedSubstr []string
		wantPreserved     []string
		wantDiffSubstr    []string
	}{
		{
			name:  "AWS_NestedBlockRemediation",
			tfDir: filepath.Join("..", "..", "testdata", "repos", "payments-aws"),
			violation: model.PolicyViolation{
				RuleID:          "AWS-S3-ENCRYPT-001",
				Severity:        "HIGH",
				Message:         "S3 bucket aws_s3_bucket.unencrypted_reports must have server-side encryption enabled",
				ResourceAddress: "aws_s3_bucket.unencrypted_reports",
				ResourceType:    "aws_s3_bucket",
				ResourceName:    "unencrypted_reports",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{
						"server_side_encryption_configuration",
						"rule",
						"apply_server_side_encryption_by_default",
						"sse_algorithm",
					},
					SuggestedVal: "aws:kms",
					Description:  "Enable server-side encryption with KMS",
				},
			},
			wantResourceAddr: "aws_s3_bucket.unencrypted_reports",
			wantPatchedSubstr: []string{
				"server_side_encryption_configuration {",
				"rule {",
				"apply_server_side_encryption_by_default {",
				`sse_algorithm = "aws:kms"`,
			},
			wantPreserved: []string{
				"# Payments Service - AWS Storage Infrastructure",
				"# Monthly financial reports bucket (currently missing server-side encryption)",
				"# Retain bucket name for downstream billing export",
				`resource "aws_s3_bucket" "compliant_audit_logs"`,
				`bucket = "company-unencrypted-reports"`,
			},
			wantDiffSubstr: []string{
				"--- a/main.tf",
				"+++ b/main.tf",
				"@@",
				"+  server_side_encryption_configuration {",
				`+        sse_algorithm = "aws:kms"`,
			},
		},
		{
			name:  "Azure_LeafAttributeRemediation",
			tfDir: filepath.Join("..", "..", "testdata", "repos", "data-azure"),
			violation: model.PolicyViolation{
				RuleID:          "AZURE-STORAGE-HTTPS-001",
				Severity:        "HIGH",
				Message:         "Storage account azurerm_storage_account.insecure_transfer must enforce HTTPS traffic only",
				ResourceAddress: "azurerm_storage_account.insecure_transfer",
				ResourceType:    "azurerm_storage_account",
				ResourceName:    "insecure_transfer",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{"https_traffic_only_enabled"},
					SuggestedVal:  true,
					Description:   "Set https_traffic_only_enabled = true",
				},
			},
			wantResourceAddr: "azurerm_storage_account.insecure_transfer",
			wantPatchedSubstr: []string{
				"https_traffic_only_enabled = true",
			},
			wantPreserved: []string{
				"# Data Platform - Azure Storage Infrastructure",
				"# Legacy data ingestion storage account (non-compliant HTTPS setting)",
				"# Legacy toggle - must be remediated to true",
				`resource "azurerm_storage_account" "compliant_lake"`,
				`name                     = "insecuretransfer"`,
				`account_replication_type = "LRS"`,
			},
			wantDiffSubstr: []string{
				"--- a/main.tf",
				"+++ b/main.tf",
				"@@",
				"-  https_traffic_only_enabled = false",
				"+  https_traffic_only_enabled = true",
			},
		},
		{
			name:  "GCP_LeafAttributeRemediation",
			tfDir: filepath.Join("..", "..", "testdata", "repos", "ml-gcp"),
			violation: model.PolicyViolation{
				RuleID:          "GCP-STORAGE-UBLA-001",
				Severity:        "MEDIUM",
				Message:         "Cloud Storage bucket google_storage_bucket.open_training_data must have uniform bucket-level access enabled",
				ResourceAddress: "google_storage_bucket.open_training_data",
				ResourceType:    "google_storage_bucket",
				ResourceName:    "open_training_data",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{"uniform_bucket_level_access"},
					SuggestedVal:  true,
					Description:   "Set uniform_bucket_level_access = true",
				},
			},
			wantResourceAddr: "google_storage_bucket.open_training_data",
			wantPatchedSubstr: []string{
				"uniform_bucket_level_access = true",
			},
			wantPreserved: []string{
				"# Machine Learning Platform - GCP Cloud Storage Infrastructure",
				"# Raw training dataset bucket (non-compliant ACL access setting)",
				"# Must enforce uniform bucket-level IAM access",
				`resource "google_storage_bucket" "secure_models"`,
				`name     = "ml-training-raw"`,
			},
			wantDiffSubstr: []string{
				"--- a/main.tf",
				"+++ b/main.tf",
				"@@",
				"-  uniform_bucket_level_access = false",
				"+  uniform_bucket_level_access = true",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patches, err := patcher.GeneratePatches(ctx, tc.tfDir, []model.PolicyViolation{tc.violation})
			if err != nil {
				t.Fatalf("GeneratePatches failed: %v", err)
			}
			if len(patches) != 1 {
				t.Fatalf("expected 1 RemediationPatch, got %d", len(patches))
			}

			patch := patches[0]
			if patch.FilePath != "main.tf" {
				t.Errorf("expected FilePath == \"main.tf\", got %q", patch.FilePath)
			}
			if patch.ResourceAddress != tc.wantResourceAddr {
				t.Errorf("expected ResourceAddress == %q, got %q", tc.wantResourceAddr, patch.ResourceAddress)
			}

			for _, sub := range tc.wantPatchedSubstr {
				if !strings.Contains(patch.PatchedHCL, sub) {
					t.Errorf("expected PatchedHCL to contain %q, got:\n%s", sub, patch.PatchedHCL)
				}
			}

			for _, pres := range tc.wantPreserved {
				if !strings.Contains(patch.PatchedHCL, pres) {
					t.Errorf("expected PatchedHCL to preserve %q, got:\n%s", pres, patch.PatchedHCL)
				}
			}

			for _, diffSub := range tc.wantDiffSubstr {
				if !strings.Contains(patch.UnifiedDiff, diffSub) {
					t.Errorf("expected UnifiedDiff to contain %q, got:\n%s", diffSub, patch.UnifiedDiff)
				}
			}

			// Verify PatchedHCL is syntactically valid HCL
			_, diags := hclwrite.ParseConfig([]byte(patch.PatchedHCL), "main.tf", hcl.Pos{Line: 1, Column: 1})
			if diags.HasErrors() {
				t.Errorf("PatchedHCL failed HCL parsing: %s", diags.Error())
			}
		})
	}
}

// TestGeneratePatches_WriteInPlaceAndReEvaluate tests in-place file modification with WithWriteChanges(true).
func TestGeneratePatches_WriteInPlaceAndReEvaluate(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	srcPath := filepath.Join("..", "..", "testdata", "repos", "data-azure", "main.tf")
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", srcPath, err)
	}

	dstPath := filepath.Join(tmpDir, "main.tf")
	if err := os.WriteFile(dstPath, srcBytes, 0o600); err != nil {
		t.Fatalf("failed to write temp main.tf: %v", err)
	}

	violation := model.PolicyViolation{
		RuleID:          "AZURE-STORAGE-HTTPS-001",
		Severity:        "HIGH",
		ResourceAddress: "azurerm_storage_account.insecure_transfer",
		ResourceType:    "azurerm_storage_account",
		ResourceName:    "insecure_transfer",
		Remediation: &model.RemediationSpec{
			AttributePath: []string{"https_traffic_only_enabled"},
			SuggestedVal:  true,
			Description:   "Set https_traffic_only_enabled = true",
		},
	}

	patcher := NewPatcher(WithWriteChanges(true))
	patches, err := patcher.GeneratePatches(ctx, tmpDir, []model.PolicyViolation{violation})
	if err != nil {
		t.Fatalf("GeneratePatches with WriteChanges(true) failed: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}

	diskBytes, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("failed to read modified main.tf from disk: %v", err)
	}
	diskStr := string(diskBytes)

	if diskStr != patches[0].PatchedHCL {
		t.Errorf("disk contents do not match PatchedHCL.\nDisk:\n%s\nPatchedHCL:\n%s", diskStr, patches[0].PatchedHCL)
	}
	if strings.Contains(diskStr, "https_traffic_only_enabled = false") {
		t.Errorf("expected https_traffic_only_enabled = false to be replaced on disk, got:\n%s", diskStr)
	}

	_, diags := hclwrite.ParseConfig(diskBytes, "main.tf", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Errorf("modified main.tf on disk failed HCL parsing: %s", diags.Error())
	}
}

// TestToCtyValue_AllSupportedTypes validates remediation across all supported SuggestedVal Go types.
func TestToCtyValue_AllSupportedTypes(t *testing.T) {
	ctx := context.Background()
	patcher := NewPatcher()

	tests := []struct {
		name         string
		attrName     string
		suggestedVal any
		wantSubstr   string
	}{
		{
			name:         "String",
			attrName:     "sse_algorithm",
			suggestedVal: "aws:kms",
			wantSubstr:   `sse_algorithm = "aws:kms"`,
		},
		{
			name:         "Bool",
			attrName:     "enabled",
			suggestedVal: true,
			wantSubstr:   "enabled = true",
		},
		{
			name:         "Int",
			attrName:     "retention_days",
			suggestedVal: 90,
			wantSubstr:   "retention_days = 90",
		},
		{
			name:         "Int64",
			attrName:     "max_size_bytes",
			suggestedVal: int64(1048576),
			wantSubstr:   "max_size_bytes = 1048576",
		},
		{
			name:         "Float64",
			attrName:     "threshold",
			suggestedVal: 0.85,
			wantSubstr:   "threshold = 0.85",
		},
		{
			name:         "JSONNumber_Int",
			attrName:     "port",
			suggestedVal: json.Number("443"),
			wantSubstr:   "port = 443",
		},
		{
			name:         "JSONNumber_Float",
			attrName:     "sampling_rate",
			suggestedVal: json.Number("0.25"),
			wantSubstr:   "sampling_rate = 0.25",
		},
		{
			name:         "StringSlice",
			attrName:     "allowed_methods",
			suggestedVal: []string{"GET", "HEAD"},
			wantSubstr:   `allowed_methods = ["GET", "HEAD"]`,
		},
		{
			name:         "StringSlice_Empty",
			attrName:     "empty_list",
			suggestedVal: []string{},
			wantSubstr:   `empty_list = []`,
		},
		{
			name:         "AnySlice",
			attrName:     "mixed_items",
			suggestedVal: []any{"tls1.2", "tls1.3"},
			wantSubstr:   `mixed_items = ["tls1.2", "tls1.3"]`,
		},
		{
			name:     "MapStringAny",
			attrName: "tags",
			suggestedVal: map[string]any{
				"Environment": "production",
				"ManagedBy":   "tf-sim",
			},
			wantSubstr: `Environment = "production"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			initialHCL := `resource "custom_resource" "target" {
  name = "example"
}
`
			if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(initialHCL), 0o600); err != nil {
				t.Fatalf("failed to write main.tf: %v", err)
			}

			v := model.PolicyViolation{
				RuleID:          "TEST-RULE-001",
				Severity:        "MEDIUM",
				ResourceAddress: "custom_resource.target",
				ResourceType:    "custom_resource",
				ResourceName:    "target",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{tc.attrName},
					SuggestedVal:  tc.suggestedVal,
				},
			}

			patches, err := patcher.GeneratePatches(ctx, tmpDir, []model.PolicyViolation{v})
			if err != nil {
				t.Fatalf("GeneratePatches failed for %s: %v", tc.name, err)
			}
			if len(patches) != 1 {
				t.Fatalf("expected 1 patch, got %d", len(patches))
			}
			if !strings.Contains(patches[0].PatchedHCL, tc.wantSubstr) {
				t.Errorf("expected PatchedHCL to contain %q, got:\n%s", tc.wantSubstr, patches[0].PatchedHCL)
			}
		})
	}
}

// TestGeneratePatches_ExistingPartialNestedBlocks verifies that existing outer blocks are reused via FirstMatchingBlock.
func TestGeneratePatches_ExistingPartialNestedBlocks(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	partialHCL := `resource "aws_s3_bucket" "partial_bucket" {
  bucket = "partial-bucket"

  server_side_encryption_configuration {
    rule {
      bucket_key_enabled = true
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(partialHCL), 0o600); err != nil {
		t.Fatalf("failed to write main.tf: %v", err)
	}

	v := model.PolicyViolation{
		RuleID:          "AWS-S3-ENCRYPT-001",
		Severity:        "HIGH",
		ResourceAddress: "aws_s3_bucket.partial_bucket",
		ResourceType:    "aws_s3_bucket",
		ResourceName:    "partial_bucket",
		Remediation: &model.RemediationSpec{
			AttributePath: []string{
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algorithm",
			},
			SuggestedVal: "aws:kms",
		},
	}

	patcher := NewPatcher()
	patches, err := patcher.GeneratePatches(ctx, tmpDir, []model.PolicyViolation{v})
	if err != nil {
		t.Fatalf("GeneratePatches failed: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}

	patched := patches[0].PatchedHCL
	if count := strings.Count(patched, "server_side_encryption_configuration"); count != 1 {
		t.Errorf("expected exactly 1 server_side_encryption_configuration block, got %d in:\n%s", count, patched)
	}
	if !strings.Contains(patched, "bucket_key_enabled = true") {
		t.Errorf("expected existing sibling attribute bucket_key_enabled = true to be preserved, got:\n%s", patched)
	}
	if !strings.Contains(patched, `sse_algorithm = "aws:kms"`) {
		t.Errorf("expected sse_algorithm = \"aws:kms\" to be added, got:\n%s", patched)
	}
}

// TestGeneratePatches_MultipleViolationsSameFile verifies cumulative mutations on the same .tf file.
func TestGeneratePatches_MultipleViolationsSameFile(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	multiHCL := `resource "azurerm_storage_account" "first" {
  name                       = "firstacct"
  https_traffic_only_enabled = false
}

resource "azurerm_storage_account" "second" {
  name                       = "secondacct"
  https_traffic_only_enabled = false
}
`
	hclPath := filepath.Join(tmpDir, "main.tf")
	if err := os.WriteFile(hclPath, []byte(multiHCL), 0o600); err != nil {
		t.Fatalf("failed to write main.tf: %v", err)
	}

	violations := []model.PolicyViolation{
		{
			RuleID:          "AZURE-STORAGE-HTTPS-001",
			Severity:        "HIGH",
			ResourceAddress: "azurerm_storage_account.first",
			ResourceType:    "azurerm_storage_account",
			ResourceName:    "first",
			Remediation: &model.RemediationSpec{
				AttributePath: []string{"https_traffic_only_enabled"},
				SuggestedVal:  true,
			},
		},
		{
			RuleID:          "AZURE-STORAGE-HTTPS-001",
			Severity:        "HIGH",
			ResourceAddress: "azurerm_storage_account.second",
			ResourceType:    "azurerm_storage_account",
			ResourceName:    "second",
			Remediation: &model.RemediationSpec{
				AttributePath: []string{"https_traffic_only_enabled"},
				SuggestedVal:  true,
			},
		},
	}

	patcher := NewPatcher(WithWriteChanges(true))
	patches, err := patcher.GeneratePatches(ctx, tmpDir, violations)
	if err != nil {
		t.Fatalf("GeneratePatches failed: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}

	diskBytes, err := os.ReadFile(hclPath)
	if err != nil {
		t.Fatalf("failed to read main.tf from disk: %v", err)
	}
	diskStr := string(diskBytes)

	if count := strings.Count(diskStr, "https_traffic_only_enabled = true"); count != 2 {
		t.Errorf("expected both resources to have https_traffic_only_enabled = true on disk, got count %d in:\n%s", count, diskStr)
	}
	if strings.Contains(diskStr, "https_traffic_only_enabled = false") {
		t.Errorf("expected zero https_traffic_only_enabled = false remaining on disk, got:\n%s", diskStr)
	}
}

// TestGeneratePatches_ViolationsWithoutRemediationOrUnmatchedResource verifies graceful skipping of non-actionable violations.
func TestGeneratePatches_ViolationsWithoutRemediationOrUnmatchedResource(t *testing.T) {
	ctx := context.Background()
	tfDir := filepath.Join("..", "..", "testdata", "repos", "data-azure")
	patcher := NewPatcher()

	t.Run("EmptyViolationsSlice", func(t *testing.T) {
		patches, err := patcher.GeneratePatches(ctx, tfDir, []model.PolicyViolation{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(patches) != 0 {
			t.Errorf("expected 0 patches, got %d", len(patches))
		}
	})

	t.Run("NilRemediationAndUnmatchedResource", func(t *testing.T) {
		violations := []model.PolicyViolation{
			{
				RuleID:          "NO-REMEDIATION-001",
				Severity:        "LOW",
				ResourceAddress: "azurerm_storage_account.insecure_transfer",
				ResourceType:    "azurerm_storage_account",
				ResourceName:    "insecure_transfer",
				Remediation:     nil,
			},
			{
				RuleID:          "UNMATCHED-RESOURCE-001",
				Severity:        "HIGH",
				ResourceAddress: "azurerm_storage_account.does_not_exist",
				ResourceType:    "azurerm_storage_account",
				ResourceName:    "does_not_exist",
				Remediation: &model.RemediationSpec{
					AttributePath: []string{"https_traffic_only_enabled"},
					SuggestedVal:  true,
				},
			},
		}

		patches, err := patcher.GeneratePatches(ctx, tfDir, violations)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(patches) != 0 {
			t.Errorf("expected 0 patches, got %d", len(patches))
		}
	})
}

// TestGeneratePatches_ModulePrefixedResourceAddress verifies fallback extraction of resource type and name from module-prefixed addresses.
func TestGeneratePatches_ModulePrefixedResourceAddress(t *testing.T) {
	ctx := context.Background()
	tfDir := filepath.Join("..", "..", "testdata", "repos", "payments-aws")
	patcher := NewPatcher()

	v := model.PolicyViolation{
		RuleID:          "AWS-S3-ENCRYPT-001",
		Severity:        "HIGH",
		ResourceAddress: "module.storage.aws_s3_bucket.unencrypted_reports",
		ResourceType:    "", // Intentionally empty to exercise fallback extraction
		ResourceName:    "", // Intentionally empty to exercise fallback extraction
		Remediation: &model.RemediationSpec{
			AttributePath: []string{
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algorithm",
			},
			SuggestedVal: "aws:kms",
		},
	}

	patches, err := patcher.GeneratePatches(ctx, tfDir, []model.PolicyViolation{v})
	if err != nil {
		t.Fatalf("GeneratePatches failed: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch from module-prefixed address fallback, got %d", len(patches))
	}
	if patches[0].ResourceAddress != "module.storage.aws_s3_bucket.unencrypted_reports" {
		t.Errorf("expected ResourceAddress to be preserved, got %q", patches[0].ResourceAddress)
	}
}

// TestGeneratePatches_CRLFNormalization verifies that Windows CRLF line endings are normalized to LF across OriginalHCL, PatchedHCL, and UnifiedDiff.
func TestGeneratePatches_CRLFNormalization(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	crlfContent := "# Header comment\r\nresource \"google_storage_bucket\" \"open_training_data\" {\r\n  name                        = \"ml-training-raw\"\r\n  uniform_bucket_level_access = false\r\n}\r\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(crlfContent), 0o600); err != nil {
		t.Fatalf("failed to write CRLF main.tf: %v", err)
	}

	v := model.PolicyViolation{
		RuleID:          "GCP-STORAGE-UBLA-001",
		Severity:        "MEDIUM",
		ResourceAddress: "google_storage_bucket.open_training_data",
		ResourceType:    "google_storage_bucket",
		ResourceName:    "open_training_data",
		Remediation: &model.RemediationSpec{
			AttributePath: []string{"uniform_bucket_level_access"},
			SuggestedVal:  true,
		},
	}

	patches, err := NewPatcher().GeneratePatches(ctx, tmpDir, []model.PolicyViolation{v})
	if err != nil {
		t.Fatalf("GeneratePatches failed: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}

	p := patches[0]
	if strings.Contains(p.OriginalHCL, "\r") {
		t.Errorf("OriginalHCL contains unnormalized CR character")
	}
	if strings.Contains(p.PatchedHCL, "\r") {
		t.Errorf("PatchedHCL contains unnormalized CR character")
	}
	if strings.Contains(p.UnifiedDiff, "\r") {
		t.Errorf("UnifiedDiff contains unnormalized CR character")
	}
}

// TestGeneratePatches_InvalidInputs tests error handling on invalid directories, malformed HCL, bad attribute paths, unsupported value types, and canceled context.
func TestGeneratePatches_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	patcher := NewPatcher()

	validViolation := model.PolicyViolation{
		RuleID:          "TEST-001",
		ResourceAddress: "azurerm_storage_account.insecure_transfer",
		ResourceType:    "azurerm_storage_account",
		ResourceName:    "insecure_transfer",
		Remediation: &model.RemediationSpec{
			AttributePath: []string{"https_traffic_only_enabled"},
			SuggestedVal:  true,
		},
	}

	t.Run("EmptyTfDir", func(t *testing.T) {
		_, err := patcher.GeneratePatches(ctx, "", []model.PolicyViolation{validViolation})
		if err == nil {
			t.Fatal("expected error for empty tfDir, got nil")
		}
	})

	t.Run("NonExistentTfDir", func(t *testing.T) {
		_, err := patcher.GeneratePatches(ctx, filepath.Join(t.TempDir(), "does-not-exist"), []model.PolicyViolation{validViolation})
		if err == nil {
			t.Fatal("expected error for non-existent tfDir, got nil")
		}
	})

	t.Run("TfDirIsRegularFile", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "file.tf")
		if err := os.WriteFile(tmpFile, []byte(""), 0o600); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		_, err := patcher.GeneratePatches(ctx, tmpFile, []model.PolicyViolation{validViolation})
		if err == nil {
			t.Fatal("expected error when tfDir is a regular file, got nil")
		}
	})

	t.Run("MalformedHCLSyntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpDir, "broken.tf"), []byte(`resource "aws_s3_bucket" "bad" { unclosed = `), 0o600); err != nil {
			t.Fatalf("failed to write broken.tf: %v", err)
		}
		_, err := patcher.GeneratePatches(ctx, tmpDir, []model.PolicyViolation{validViolation})
		if err == nil || !strings.Contains(err.Error(), "parsing HCL file") {
			t.Fatalf("expected error containing 'parsing HCL file', got: %v", err)
		}
	})

	t.Run("EmptyAttributePathSegment", func(t *testing.T) {
		tfDir := filepath.Join("..", "..", "testdata", "repos", "data-azure")
		badViolation := validViolation
		badViolation.Remediation = &model.RemediationSpec{
			AttributePath: []string{"outer", "   ", "leaf"},
			SuggestedVal:  true,
		}
		_, err := patcher.GeneratePatches(ctx, tfDir, []model.PolicyViolation{badViolation})
		if err == nil {
			t.Fatal("expected error for whitespace-only attribute path segment, got nil")
		}
	})

	t.Run("UnsupportedSuggestedValType", func(t *testing.T) {
		tfDir := filepath.Join("..", "..", "testdata", "repos", "data-azure")
		badViolation := validViolation
		badViolation.Remediation = &model.RemediationSpec{
			AttributePath: []string{"https_traffic_only_enabled"},
			SuggestedVal:  struct{ Custom int }{Custom: 42},
		}
		_, err := patcher.GeneratePatches(ctx, tfDir, []model.PolicyViolation{badViolation})
		if err == nil || !strings.Contains(err.Error(), "unsupported remediation suggested_value type") {
			t.Fatalf("expected unsupported suggested_value type error, got: %v", err)
		}
	})

	t.Run("CanceledContext", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		tfDir := filepath.Join("..", "..", "testdata", "repos", "data-azure")
		_, err := patcher.GeneratePatches(canceledCtx, tfDir, []model.PolicyViolation{validViolation})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled error, got: %v", err)
		}
	})
}

// TestApplyPatches_PathTraversalAndSymlinkProtection validates security boundaries when writing patched HCL to disk.
func TestApplyPatches_PathTraversalAndSymlinkProtection(t *testing.T) {
	ctx := context.Background()
	patcher := NewPatcher()

	t.Run("RelativePathTraversalRejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		patches := []model.RemediationPatch{
			{
				FilePath:        "../outside.tf",
				ResourceAddress: "aws_s3_bucket.bad",
				PatchedHCL:      "# malicious write\n",
			},
		}
		err := patcher.ApplyPatches(ctx, tmpDir, patches)
		if err == nil {
			t.Fatal("expected path traversal error for ../outside.tf, got nil")
		}
	})

	t.Run("DeepPathTraversalRejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		patches := []model.RemediationPatch{
			{
				FilePath:        "../../etc/passwd",
				ResourceAddress: "aws_s3_bucket.bad",
				PatchedHCL:      "# malicious write\n",
			},
		}
		err := patcher.ApplyPatches(ctx, tmpDir, patches)
		if err == nil {
			t.Fatal("expected path traversal error for ../../etc/passwd, got nil")
		}
	})

	t.Run("AbsoluteFilePathRejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		absTarget := filepath.Join(tmpDir, "main.tf")
		patches := []model.RemediationPatch{
			{
				FilePath:        absTarget,
				ResourceAddress: "aws_s3_bucket.bad",
				PatchedHCL:      "# malicious write\n",
			},
		}
		err := patcher.ApplyPatches(ctx, tmpDir, patches)
		if err == nil {
			t.Fatal("expected error for absolute FilePath in RemediationPatch, got nil")
		}
	})

	t.Run("SymlinkTargetRejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "secret.tf")
		if err := os.WriteFile(outsideFile, []byte("# original secret\n"), 0o600); err != nil {
			t.Fatalf("failed to create outside file: %v", err)
		}

		symlinkPath := filepath.Join(tmpDir, "symlink.tf")
		if err := os.Symlink(outsideFile, symlinkPath); err != nil {
			t.Skipf("skipping symlink test because OS/environment does not permit os.Symlink: %v", err)
		}

		patches := []model.RemediationPatch{
			{
				FilePath:        "symlink.tf",
				ResourceAddress: "aws_s3_bucket.bad",
				PatchedHCL:      "# overwritten via symlink\n",
			},
		}
		err := patcher.ApplyPatches(ctx, tmpDir, patches)
		if err == nil {
			t.Fatal("expected ApplyPatches to reject symlink target, got nil")
		}

		secretBytes, readErr := os.ReadFile(outsideFile)
		if readErr != nil {
			t.Fatalf("failed to read outsideFile: %v", readErr)
		}
		if string(secretBytes) != "# original secret\n" {
			t.Errorf("outsideFile was modified through symlink! got: %q", string(secretBytes))
		}
	})
}
