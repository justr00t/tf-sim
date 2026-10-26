package verifier_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boomer/tf-sim/internal/model"
	"github.com/boomer/tf-sim/internal/parser"
	"github.com/boomer/tf-sim/internal/verifier"
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
