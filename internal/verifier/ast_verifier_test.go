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
