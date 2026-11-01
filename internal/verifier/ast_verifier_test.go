package verifier_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/verifier"
)

func TestVerifyPolicy_ValidMultiCloud(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	v := verifier.NewVerifier()

	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil VerificationResult")
	}
	if !res.Valid {
		t.Errorf("expected Valid == true, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	if res.PackageName != "tfsim" {
		t.Errorf("expected PackageName == 'tfsim', got %q", res.PackageName)
	}
	if res.PolicyPath != policyPath {
		t.Errorf("expected PolicyPath == %q, got %q", policyPath, res.PolicyPath)
	}
}

func TestVerifyPolicy_CatchFailOpenTypos(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "broken_fail_open.rego")
	v := verifier.NewVerifier()

	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil VerificationResult")
	}
	if res.Valid {
		t.Fatalf("expected Valid == false for broken policy with fail-open typos, got true")
	}
	if len(res.Diagnostics) < 2 {
		t.Fatalf("expected at least 2 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}

	var foundAzureTypo, foundAwsTypo bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "azurerm_storage_account" && diag.InvalidPath == "https_only_enabled" {
			foundAzureTypo = true
			if diag.Severity != "ERROR" {
				t.Errorf("expected Severity == ERROR for azure typo, got %q", diag.Severity)
			}
			if diag.Line != 14 {
				t.Errorf("expected line 14 for azure typo, got line %d", diag.Line)
			}
			if !strings.Contains(diag.Message, "https_only_enabled") {
				t.Errorf("expected message to mention 'https_only_enabled', got %q", diag.Message)
			}
		}
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "invalid_encrypt" {
			foundAwsTypo = true
			if diag.Severity != "ERROR" {
				t.Errorf("expected Severity == ERROR for aws typo, got %q", diag.Severity)
			}
			if diag.Line != 30 {
				t.Errorf("expected line 30 for aws typo, got line %d", diag.Line)
			}
			if !strings.Contains(diag.Message, "invalid_encrypt") {
				t.Errorf("expected message to mention 'invalid_encrypt', got %q", diag.Message)
			}
		}
	}

	if !foundAzureTypo {
		t.Errorf("did not find expected diagnostic for azurerm_storage_account.https_only_enabled; diagnostics: %+v", res.Diagnostics)
	}
	if !foundAwsTypo {
		t.Errorf("did not find expected diagnostic for aws_s3_bucket.invalid_encrypt; diagnostics: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_UnknownResourceType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_nonexistent_bucket"
	rc.change.after.foo == true
	violation := {
		"rule_id": "UNKNOWN-001",
		"severity": "HIGH",
		"message": "test unknown",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "unknown_type.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid == false for unknown resource type, got true")
	}

	var foundUnknownType bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "aws_nonexistent_bucket" && strings.Contains(strings.ToLower(diag.Message), "unknown resource type") {
			foundUnknownType = true
			if diag.Severity != "ERROR" {
				t.Errorf("expected Severity == ERROR for unknown resource type, got %q", diag.Severity)
			}
		}
	}
	if !foundUnknownType {
		t.Errorf("expected diagnostic mentioning unknown resource type 'aws_nonexistent_bucket', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_MissingEnforcementEntrypoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

helper_func if {
	true
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "no_entrypoint.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid == false for policy missing deny/violation rules, got true")
	}

	var foundEntrypointDiag bool
	for _, diag := range res.Diagnostics {
		msg := strings.ToLower(diag.Message)
		if strings.Contains(msg, "deny") && strings.Contains(msg, "violation") {
			foundEntrypointDiag = true
			if diag.Severity != "ERROR" {
				t.Errorf("expected Severity == ERROR, got %q", diag.Severity)
			}
		}
	}
	if !foundEntrypointDiag {
		t.Errorf("expected diagnostic mentioning missing 'deny' or 'violation' entrypoint, got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_SyntaxError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "syntax_error.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid == false for syntax error, got true")
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics for syntax error, got 0")
	}

	firstDiag := res.Diagnostics[0]
	if firstDiag.Severity != "ERROR" {
		t.Errorf("expected Severity == ERROR for syntax error, got %q", firstDiag.Severity)
	}
	if firstDiag.Line <= 0 {
		t.Errorf("expected positive line number for syntax error, got %d", firstDiag.Line)
	}
	if firstDiag.Message == "" {
		t.Errorf("expected non-empty message for syntax error")
	}
}

func TestVerifyPolicy_UnboundVariable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	x == 1
	violation := {
		"rule_id": "UNBOUND-001",
		"severity": "HIGH",
		"message": "unbound variable test",
		"resource_address": "test",
		"resource_type": "test",
		"resource_name": "test",
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "unbound_var.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Errorf("expected Valid == false for unbound variable, got true")
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics for unbound variable, got 0")
	}

	var foundUnboundDiag bool
	for _, diag := range res.Diagnostics {
		msg := strings.ToLower(diag.Message)
		if strings.Contains(msg, "unsafe") || strings.Contains(msg, "unbound") || strings.Contains(msg, "x") {
			foundUnboundDiag = true
			if diag.Severity != "ERROR" {
				t.Errorf("expected Severity == ERROR for compiler error, got %q", diag.Severity)
			}
		}
	}
	if !foundUnboundDiag {
		t.Errorf("expected diagnostic mentioning unsafe/unbound variable 'x', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_EmptySchemaMap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	emptySchemas := model.ProviderSchemaMap{}
	v := verifier.NewVerifier()

	res, err := v.VerifyPolicy(ctx, policyPath, emptySchemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true when schemas are empty, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics with empty schemas, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPolicy_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	v := verifier.NewVerifier()

	_, err := v.VerifyPolicy(ctx, policyPath, model.ProviderSchemaMap{})
	if err == nil {
		t.Fatal("expected error with cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to be context.Canceled, got %v", err)
	}
}

func TestVerifyPolicy_NonexistentFile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join(t.TempDir(), "nonexistent_policy.rego")
	v := verifier.NewVerifier()

	_, err := v.VerifyPolicy(ctx, policyPath, model.ProviderSchemaMap{})
	if err == nil {
		t.Fatal("expected error reading nonexistent policy file, got nil")
	}
}

func TestVerifyPolicy_MapObjectDynamicChildAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.tags.Environment != "prod"
	rc.change.after.tags["CostCenter"] != "cc-100"
	violation := {
		"rule_id": "AWS-TAGS-001",
		"severity": "MEDIUM",
		"message": "missing required tags",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.tags.Environment != "prod"
	rc.change.after.tags["CostCenter"] != "cc-200"
	violation := {
		"rule_id": "AZURE-TAGS-001",
		"severity": "MEDIUM",
		"message": "missing required tags",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	t := rc.change.after.labels
	t.team == "ml"
	violation := {
		"rule_id": "GCP-LABELS-001",
		"severity": "LOW",
		"message": "ml team label check",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "map_child_access.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for map child key access, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPolicy_MultiTypeRule_ValidSharedAttribute(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type in ["aws_s3_bucket", "azurerm_storage_account"]
	rc.change.after.tags.Environment == "prod"
	violation := {
		"rule_id": "MULTI-ARRAY-001",
		"severity": "MEDIUM",
		"message": "shared tags check via array literal",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type in {"aws_s3_bucket", "azurerm_storage_account"}
	rc.change.after.tags.Environment == "prod"
	violation := {
		"rule_id": "MULTI-SET-001",
		"severity": "MEDIUM",
		"message": "shared tags check via set literal",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "multi_type_valid.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for valid shared attribute across multi-type rules, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPolicy_MultiTypeRule_HelperPropagation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type in ["aws_s3_bucket", "azurerm_storage_account"]
	has_required_tags(rc)
	violation := {
		"rule_id": "MULTI-HELPER-001",
		"severity": "HIGH",
		"message": "helper propagation test",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

has_required_tags(rc) if {
	rc.change.after.invalid_helper_attr == true
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "multi_type_helper.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when helper accesses invalid attribute, got true")
	}

	var foundAWS, foundAzure bool
	for _, diag := range res.Diagnostics {
		if diag.InvalidPath == "invalid_helper_attr" && diag.Severity == "ERROR" {
			switch diag.ResourceType {
			case "aws_s3_bucket":
				foundAWS = true
			case "azurerm_storage_account":
				foundAzure = true
			}
		}
	}
	if !foundAWS {
		t.Errorf("expected ERROR diagnostic for aws_s3_bucket.invalid_helper_attr inside helper rule, got: %+v", res.Diagnostics)
	}
	if !foundAzure {
		t.Errorf("expected ERROR diagnostic for azurerm_storage_account.invalid_helper_attr inside helper rule, got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_DynamicAndObjectSchemaAttributes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemas := model.ProviderSchemaMap{
		"kubernetes_manifest": {
			ResourceType: "kubernetes_manifest",
			Attributes: map[string]model.AttributeDef{
				"custom_obj": {
					Name:     "custom_obj",
					Type:     "object",
					Optional: true,
				},
				"manifest": {
					Name:     "manifest",
					Type:     "dynamic",
					Required: true,
				},
			},
		},
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "kubernetes_manifest"
	rc.change.after.custom_obj.nested.field == "expected"
	rc.change.after.manifest.metadata.name == "my-app"
	violation := {
		"rule_id": "K8S-OBJ-DYN-001",
		"severity": "HIGH",
		"message": "object and dynamic nested traversal",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "dynamic_object_schema.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for object and dynamic attributes without NestedBlocks, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPolicy_MultiTypeRule_InvalidAttrOnFirstOrSecondType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type in ["aws_s3_bucket", "azurerm_storage_account"]
	rc.change.after.https_traffic_only_enabled == false
	rc.change.after.bucket == "my-bucket"
	violation := {
		"rule_id": "MULTI-INVALID-001",
		"severity": "HIGH",
		"message": "cross-type invalid attribute check",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "multi_type_invalid_both.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when attributes are invalid on first or second resource type, got true")
	}

	var foundInvalidOnFirst, foundInvalidOnSecond bool
	for _, diag := range res.Diagnostics {
		if diag.Severity != "ERROR" {
			continue
		}
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "https_traffic_only_enabled" {
			foundInvalidOnFirst = true
		}
		if diag.ResourceType == "azurerm_storage_account" && diag.InvalidPath == "bucket" {
			foundInvalidOnSecond = true
		}
	}

	if !foundInvalidOnFirst {
		t.Errorf("expected ERROR diagnostic for https_traffic_only_enabled on aws_s3_bucket, got: %+v", res.Diagnostics)
	}
	if !foundInvalidOnSecond {
		t.Errorf("expected ERROR diagnostic for bucket on azurerm_storage_account, got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_MultiTypeRule_SetLiteral_InvalidAttr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type in {"aws_s3_bucket", "google_storage_bucket"}
	rc.change.after.uniform_bucket_level_access == false
	violation := {
		"rule_id": "MULTI-SET-INVALID-001",
		"severity": "HIGH",
		"message": "set literal invalid attr check",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "multi_type_set_invalid.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when set literal rule accesses attribute missing on aws_s3_bucket, got true")
	}

	var foundAWS bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "uniform_bucket_level_access" && diag.Severity == "ERROR" {
			foundAWS = true
		}
		if diag.ResourceType == "google_storage_bucket" && diag.InvalidPath == "uniform_bucket_level_access" {
			t.Errorf("unexpected diagnostic for uniform_bucket_level_access on google_storage_bucket: %+v", diag)
		}
	}
	if !foundAWS {
		t.Errorf("expected ERROR diagnostic for uniform_bucket_level_access on aws_s3_bucket, got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_MapTypoAndPrimitiveChildAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.tgas.Environment == "prod"
	rc.change.after.bucket.sub_field == "invalid"
	violation := {
		"rule_id": "AWS-TYPO-PRIMITIVE-001",
		"severity": "HIGH",
		"message": "map typo and primitive child access",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "map_typo_primitive_child.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false for map typo and primitive child access, got true")
	}

	var foundTgasTypo, foundBucketPrimitive bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "tgas" && diag.Severity == "ERROR" {
			if strings.Contains(diag.Message, "does not exist") {
				foundTgasTypo = true
			}
		}
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "bucket" && diag.Severity == "ERROR" {
			if strings.Contains(diag.Message, "is not a nested block") {
				foundBucketPrimitive = true
			}
		}
	}

	if !foundTgasTypo {
		t.Errorf("expected ERROR diagnostic for InvalidPath 'tgas' ('does not exist'), got: %+v", res.Diagnostics)
	}
	if !foundBucketPrimitive {
		t.Errorf("expected ERROR diagnostic for InvalidPath 'bucket' ('is not a nested block'), got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_RemediationAttributePath_Valid(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

# 1. Inline remediation.attribute_path in rule body (nested blocks + leaf attribute)
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.bucket == "my-bucket"
	violation := {
		"rule_id": "AWS-S3-REM-VALID-001",
		"severity": "HIGH",
		"message": "inline body nested remediation path",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": [
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algorithm",
			],
			"suggested_value": "aws:kms",
		},
	}
}

# 2. Inline remediation.attribute_path directly in rule head
deny contains {
	"rule_id": "AZURE-HTTPS-REM-VALID-001",
	"severity": "HIGH",
	"message": "inline head top-level remediation path",
	"resource_address": rc.address,
	"resource_type": rc.type,
	"resource_name": rc.name,
	"remediation": {
		"attribute_path": ["https_traffic_only_enabled"],
		"suggested_value": true,
	},
} if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.https_traffic_only_enabled == false
}

# 3. Remediation via local variables (rem := {...} and path := [...]) and under a map attribute
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.tags.Environment != "prod"
	path := ["tags", "Environment"]
	rem := {
		"attribute_path": path,
		"suggested_value": "prod",
	}
	violation := {
		"rule_id": "AWS-TAGS-REM-VALID-001",
		"severity": "MEDIUM",
		"message": "local variable map remediation path",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": rem,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "remediation_valid.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for valid remediation attribute_path forms, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPolicies_MultiFile_ValidWithSharedHelpers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	helpersContent := `package tfsim

import rego.v1

is_delete(rc) if {
	rc.change.actions == ["delete"]
}

has_s3_encryption(rc) if {
	some ssec in rc.change.after.server_side_encryption_configuration
	some r in ssec.rule
	some d in r.apply_server_side_encryption_by_default
	d.sse_algorithm in ["aws:kms", "AES256"]
}
`

	rulesContent := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not is_delete(rc)
	not has_s3_encryption(rc)
	violation := {
		"rule_id": "AWS-S3-MULTI-001",
		"severity": "HIGH",
		"message": "S3 bucket missing server-side encryption",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": [
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algorithm",
			],
			"suggested_value": "aws:kms",
		},
	}
}
`
	tmpDir := t.TempDir()
	helpersPath := filepath.Join(tmpDir, "helpers.rego")
	rulesPath := filepath.Join(tmpDir, "rules.rego")
	if err := os.WriteFile(helpersPath, []byte(helpersContent), 0644); err != nil {
		t.Fatalf("failed to write helpers.rego: %v", err)
	}
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("failed to write rules.rego: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicies(ctx, []string{helpersPath, rulesPath}, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicies returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for valid multi-file policies, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	if !strings.Contains(res.PolicyPath, helpersPath) || !strings.Contains(res.PolicyPath, rulesPath) {
		t.Errorf("expected PolicyPath to contain both %q and %q, got %q", helpersPath, rulesPath, res.PolicyPath)
	}
}

func TestVerifyPolicy_RemediationAttributePath_LeafIsNestedBlock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.bucket == "my-bucket"
	violation := {
		"rule_id": "AWS-S3-LEAF-BLOCK-001",
		"severity": "HIGH",
		"message": "leaf segment is nested block instead of attribute",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["server_side_encryption_configuration", "rule"],
			"suggested_value": "aws:kms",
		},
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "leaf_nested_block.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when remediation.attribute_path leaf is a nested block, got true")
	}

	var foundNestedBlockDiag bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "rule" && diag.Severity == "ERROR" {
			if strings.Contains(strings.ToLower(diag.Message), "nested block") {
				foundNestedBlockDiag = true
			}
		}
	}
	if !foundNestedBlockDiag {
		t.Errorf("expected ERROR diagnostic with InvalidPath == 'rule' mentioning 'nested block', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicy_RemediationAttributePath_InRuleHeadAndLocalVars(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains {
	"rule_id": "AZURE-HEAD-TYPO-001",
	"severity": "HIGH",
	"message": "typo in rule head remediation",
	"resource_address": rc.address,
	"resource_type": rc.type,
	"resource_name": rc.name,
	"remediation": {
		"attribute_path": ["typo_in_head"],
		"suggested_value": true,
	},
} if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.https_traffic_only_enabled == false
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.bucket == "my-bucket"
	p := ["typo_in_var"]
	rem := {
		"attribute_path": p,
		"suggested_value": "aws:kms",
	}
	violation := {
		"rule_id": "AWS-VAR-TYPO-001",
		"severity": "HIGH",
		"message": "typo in local var remediation",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": rem,
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "head_and_local_vars_typo.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false for remediation typos in head and local vars, got true")
	}

	var foundHeadTypo, foundVarTypo bool
	for _, diag := range res.Diagnostics {
		if diag.Severity != "ERROR" {
			continue
		}
		if diag.ResourceType == "azurerm_storage_account" && diag.InvalidPath == "typo_in_head" {
			foundHeadTypo = true
		}
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "typo_in_var" {
			foundVarTypo = true
		}
	}
	if !foundHeadTypo {
		t.Errorf("expected ERROR diagnostic for InvalidPath == 'typo_in_head', got: %+v", res.Diagnostics)
	}
	if !foundVarTypo {
		t.Errorf("expected ERROR diagnostic for InvalidPath == 'typo_in_var', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicies_MultiFile_CrossFileHelperInvalidAttr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	helpersContent := `package tfsim

import rego.v1

check_s3(rc) if {
	rc.change.after.nonexistent_helper_attr == true
}
`

	rulesContent := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	check_s3(rc)
	violation := {
		"rule_id": "AWS-CROSS-HELPER-001",
		"severity": "HIGH",
		"message": "cross-file helper check",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	tmpDir := t.TempDir()
	helpersPath := filepath.Join(tmpDir, "helpers.rego")
	rulesPath := filepath.Join(tmpDir, "rules.rego")
	if err := os.WriteFile(helpersPath, []byte(helpersContent), 0644); err != nil {
		t.Fatalf("failed to write helpers.rego: %v", err)
	}
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("failed to write rules.rego: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicies(ctx, []string{rulesPath, helpersPath}, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicies returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when cross-file helper accesses invalid attribute, got true")
	}

	var foundHelperDiag bool
	for _, diag := range res.Diagnostics {
		if diag.PolicyFile == helpersPath &&
			diag.ResourceType == "aws_s3_bucket" &&
			diag.InvalidPath == "nonexistent_helper_attr" &&
			diag.Severity == "ERROR" {
			foundHelperDiag = true
		}
	}
	if !foundHelperDiag {
		t.Errorf("expected ERROR diagnostic attributed to PolicyFile %q with ResourceType 'aws_s3_bucket' and InvalidPath 'nonexistent_helper_attr', got: %+v", helpersPath, res.Diagnostics)
	}
}

func TestVerifyPolicy_RemediationAttributePath_InvalidLeafAndIntermediate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	content := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.bucket == "my-bucket"
	violation := {
		"rule_id": "AWS-S3-LEAF-TYPO-001",
		"severity": "HIGH",
		"message": "leaf typo",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": [
				"server_side_encryption_configuration",
				"rule",
				"apply_server_side_encryption_by_default",
				"sse_algo_typo",
			],
			"suggested_value": "aws:kms",
		},
	}
}

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.after.bucket == "my-bucket"
	violation := {
		"rule_id": "AWS-S3-INTERMEDIATE-TYPO-001",
		"severity": "HIGH",
		"message": "intermediate typo",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": [
				"server_side_encryption_config_typo",
				"rule",
				"sse_algorithm",
			],
			"suggested_value": "aws:kms",
		},
	}
}
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "invalid_leaf_and_intermediate.rego")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	v := verifier.NewVerifier()
	res, err := v.VerifyPolicy(ctx, policyPath, schemas)
	if err != nil {
		t.Fatalf("VerifyPolicy returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false for leaf and intermediate remediation path typos, got true")
	}

	var foundLeafTypo, foundIntermediateTypo bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "sse_algo_typo" && diag.Severity == "ERROR" {
			foundLeafTypo = true
			if diag.Line != 21 {
				t.Errorf("expected line 21 for 'sse_algo_typo', got line %d", diag.Line)
			}
		}
		if diag.ResourceType == "aws_s3_bucket" && diag.InvalidPath == "server_side_encryption_config_typo" && diag.Severity == "ERROR" {
			foundIntermediateTypo = true
			if diag.Line != 41 {
				t.Errorf("expected line 41 for 'server_side_encryption_config_typo', got line %d", diag.Line)
			}
		}
	}
	if !foundLeafTypo {
		t.Errorf("expected ERROR diagnostic for 'sse_algo_typo', got: %+v", res.Diagnostics)
	}
	if !foundIntermediateTypo {
		t.Errorf("expected ERROR diagnostic for 'server_side_encryption_config_typo', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPolicies_EmptyPathsAndMissingSecondFile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	v := verifier.NewVerifier()
	schemas := model.ProviderSchemaMap{}

	_, err := v.VerifyPolicies(ctx, []string{}, schemas)
	if err == nil {
		t.Fatal("expected error when policyPaths is empty, got nil")
	}
	if !strings.Contains(err.Error(), "at least one policy path must be provided") {
		t.Errorf("expected error to contain 'at least one policy path must be provided', got %q", err.Error())
	}

	validPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	missingPath := filepath.Join(t.TempDir(), "missing_second_file.rego")

	_, err = v.VerifyPolicies(ctx, []string{validPath, missingPath}, schemas)
	if err == nil {
		t.Fatal("expected error when second policy file does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "stat policy file") {
		t.Errorf("expected error to contain 'stat policy file', got %q", err.Error())
	}
}

const compliantFixturePlanJSON = `{
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

func TestVerifyPoliciesWithFixtures_ValidPolicyAndMatchingFixtures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	tmpDir := t.TempDir()
	passPlan := filepath.Join(tmpDir, "compliant.json")
	if err := os.WriteFile(passPlan, []byte(compliantFixturePlanJSON), 0o600); err != nil {
		t.Fatalf("failed to write compliant fixture plan: %v", err)
	}

	failPlanAWS := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")
	failPlanAzure := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")

	v := verifier.NewVerifier()
	res, err := v.VerifyPoliciesWithFixtures(
		ctx,
		[]string{policyPath},
		schemas,
		[]string{passPlan},
		[]string{failPlanAWS, failPlanAzure},
	)
	if err != nil {
		t.Fatalf("VerifyPoliciesWithFixtures returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}

	// Backward compatibility when passFixturePaths and failFixturePaths are nil
	resNoFixtures, err := v.VerifyPoliciesWithFixtures(ctx, []string{policyPath}, schemas, nil, nil)
	if err != nil {
		t.Fatalf("VerifyPoliciesWithFixtures(nil, nil) returned unexpected error: %v", err)
	}
	if !resNoFixtures.Valid || len(resNoFixtures.Diagnostics) != 0 {
		t.Errorf("expected Valid == true with 0 diagnostics when fixtures are nil, got: %+v", resNoFixtures)
	}
}

func TestVerifyPoliciesWithFixtures_DirectoryFixtures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}

	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	passDir := t.TempDir()
	for _, name := range []string{"pass_one.json", "pass_two.json"} {
		if err := os.WriteFile(filepath.Join(passDir, name), []byte(compliantFixturePlanJSON), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
	failDir := filepath.Join("..", "..", "testdata", "plans")

	v := verifier.NewVerifier()
	res, err := v.VerifyPoliciesWithFixtures(
		ctx,
		[]string{policyPath},
		schemas,
		[]string{passDir},
		[]string{failDir},
	)
	if err != nil {
		t.Fatalf("VerifyPoliciesWithFixtures with directories returned unexpected error: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected Valid == true for directory fixtures, got false with diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("expected 0 diagnostics, got %d: %+v", len(res.Diagnostics), res.Diagnostics)
	}
}

func TestVerifyPoliciesWithFixtures_PassFixtureHasViolations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policyPath := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	nonCompliantPlan := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

	v := verifier.NewVerifier()
	res, err := v.VerifyPoliciesWithFixtures(
		ctx,
		[]string{policyPath},
		model.ProviderSchemaMap{},
		[]string{nonCompliantPlan},
		nil,
	)
	if err != nil {
		t.Fatalf("VerifyPoliciesWithFixtures returned unexpected error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected Valid == false when pass fixture produces violations, got true")
	}

	var foundPassDiag bool
	for _, diag := range res.Diagnostics {
		if diag.ResourceType == "fixture:pass" && diag.Severity == "ERROR" {
			if strings.Contains(diag.Message, "AWS-S3-ENCRYPT-001") {
				foundPassDiag = true
			}
		}
	}
	if !foundPassDiag {
		t.Errorf("expected ERROR diagnostic with ResourceType 'fixture:pass' mentioning 'AWS-S3-ENCRYPT-001', got: %+v", res.Diagnostics)
	}
}

func TestVerifyPoliciesWithFixtures_FailFixturePassesSilently_CatchesFailOpen(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	failPlanAzure := filepath.Join("..", "..", "testdata", "plans", "repo_data_azure.json")

	t.Run("LogicalFailOpenPolicy_WithoutSchema", func(t *testing.T) {
		// Schema-valid attribute name, but logical fail-open bug (requires action == delete instead of not delete)
		logicalFailOpenRego := `package tfsim

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.actions == ["delete"]
	rc.change.after.https_traffic_only_enabled == false
	violation := {
		"rule_id": "AZURE-INVERTED-001",
		"severity": "HIGH",
		"message": "inverted logic bug",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "inverted_logic.rego")
		if err := os.WriteFile(policyPath, []byte(logicalFailOpenRego), 0o600); err != nil {
			t.Fatalf("failed to write inverted_logic.rego: %v", err)
		}

		v := verifier.NewVerifier()
		res, err := v.VerifyPoliciesWithFixtures(
			ctx,
			[]string{policyPath},
			model.ProviderSchemaMap{},
			nil,
			[]string{failPlanAzure},
		)
		if err != nil {
			t.Fatalf("VerifyPoliciesWithFixtures returned unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatalf("expected Valid == false when fail fixture passes silently, got true")
		}

		var foundFailDiag bool
		for _, diag := range res.Diagnostics {
			if diag.ResourceType == "fixture:fail" && diag.Severity == "ERROR" && strings.Contains(diag.Message, "potential silent fail-open bug") {
				foundFailDiag = true
			}
		}
		if !foundFailDiag {
			t.Errorf("expected fixture:fail diagnostic mentioning 'potential silent fail-open bug', got: %+v", res.Diagnostics)
		}
	})

	t.Run("BrokenFailOpenPolicy_WithSchemaAndFailFixture", func(t *testing.T) {
		p := parser.NewParser()
		schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")
		schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
		if err != nil {
			t.Fatalf("LoadProviderSchemas failed: %v", err)
		}

		brokenPolicyPath := filepath.Join("..", "..", "testdata", "policies", "broken_fail_open.rego")
		v := verifier.NewVerifier()
		res, err := v.VerifyPoliciesWithFixtures(
			ctx,
			[]string{brokenPolicyPath},
			schemas,
			nil,
			[]string{failPlanAzure},
		)
		if err != nil {
			t.Fatalf("VerifyPoliciesWithFixtures returned unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatalf("expected Valid == false, got true")
		}

		var foundSchemaTypo, foundFixtureFail bool
		for _, diag := range res.Diagnostics {
			if diag.ResourceType == "azurerm_storage_account" && diag.InvalidPath == "https_only_enabled" {
				foundSchemaTypo = true
			}
			if diag.ResourceType == "fixture:fail" && strings.Contains(diag.Message, "potential silent fail-open bug") {
				foundFixtureFail = true
			}
		}
		if !foundSchemaTypo {
			t.Errorf("expected schema typo diagnostic for https_only_enabled, got: %+v", res.Diagnostics)
		}
		if !foundFixtureFail {
			t.Errorf("expected fixture:fail diagnostic proving broken_fail_open.rego failed open, got: %+v", res.Diagnostics)
		}
	})
}

func TestVerifyPoliciesWithFixtures_ErrorCases(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	validPolicy := filepath.Join("..", "..", "testdata", "policies", "storage_encryption.rego")
	v := verifier.NewVerifier()

	t.Run("NonexistentPassFixture", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nonexistent_pass.json")
		_, err := v.VerifyPoliciesWithFixtures(ctx, []string{validPolicy}, model.ProviderSchemaMap{}, []string{missing}, nil)
		if err == nil {
			t.Fatal("expected error for nonexistent pass fixture file, got nil")
		}
	})

	t.Run("NonexistentFailFixture", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nonexistent_fail.json")
		_, err := v.VerifyPoliciesWithFixtures(ctx, []string{validPolicy}, model.ProviderSchemaMap{}, nil, []string{missing})
		if err == nil {
			t.Fatal("expected error for nonexistent fail fixture file, got nil")
		}
	})

	t.Run("EmptyFixtureDirectory", func(t *testing.T) {
		emptyDir := t.TempDir()
		_, err := v.VerifyPoliciesWithFixtures(ctx, []string{validPolicy}, model.ProviderSchemaMap{}, []string{emptyDir}, nil)
		if err == nil || !strings.Contains(err.Error(), "contains no .json plan files") {
			t.Fatalf("expected error containing 'contains no .json plan files', got: %v", err)
		}
	})

	t.Run("MalformedJSONFixture", func(t *testing.T) {
		tmpDir := t.TempDir()
		badJSON := filepath.Join(tmpDir, "bad.json")
		if err := os.WriteFile(badJSON, []byte("{not valid json"), 0o600); err != nil {
			t.Fatalf("failed to write bad.json: %v", err)
		}
		_, err := v.VerifyPoliciesWithFixtures(ctx, []string{validPolicy}, model.ProviderSchemaMap{}, []string{badJSON}, nil)
		if err == nil {
			t.Fatal("expected error for malformed JSON fixture, got nil")
		}
	})

	t.Run("PolicyWithSyntaxOrEntrypointError_ReturnsInvalidResultNotRuntimeError", func(t *testing.T) {
		tmpDir := t.TempDir()
		passPlan := filepath.Join(tmpDir, "compliant.json")
		if err := os.WriteFile(passPlan, []byte(compliantFixturePlanJSON), 0o600); err != nil {
			t.Fatalf("failed to write compliant.json: %v", err)
		}

		noEntrypointPolicy := filepath.Join(tmpDir, "no_entrypoint.rego")
		content := "package tfsim\nimport rego.v1\nhelper if { true }\n"
		if err := os.WriteFile(noEntrypointPolicy, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write no_entrypoint.rego: %v", err)
		}

		res, err := v.VerifyPoliciesWithFixtures(ctx, []string{noEntrypointPolicy}, model.ProviderSchemaMap{}, []string{passPlan}, nil)
		if err != nil {
			t.Fatalf("expected nil operational error when policy lacks deny entrypoint, got: %v", err)
		}
		if res == nil || res.Valid {
			t.Fatalf("expected res.Valid == false for policy missing deny entrypoint, got: %+v", res)
		}
	})
}
