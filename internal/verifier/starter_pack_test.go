package verifier_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/policy"
	"github.com/justr00t/tf-sim/internal/verifier"
)

func TestVerifyPoliciesContents_AllStarterPacks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "starter_pack_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas(%s) failed: %v", schemaPath, err)
	}

	v := verifier.NewVerifier()
	for _, packName := range []string{"aws", "azure", "gcp", "all"} {
		t.Run("Pack_"+packName, func(t *testing.T) {
			t.Parallel()

			policies, err := policy.LoadPolicies(nil, []string{packName})
			if err != nil {
				t.Fatalf("LoadPolicies(%q) failed: %v", packName, err)
			}

			res, err := v.VerifyPoliciesContents(ctx, policies, schemas)
			if err != nil {
				t.Fatalf("VerifyPoliciesContents(%q) returned unexpected error: %v", packName, err)
			}
			if res == nil {
				t.Fatal("expected non-nil VerificationResult")
			}
			if !res.Valid || len(res.Diagnostics) != 0 {
				t.Errorf("pack %q failed AST/schema verification: Valid=%v, Diagnostics=%+v", packName, res.Valid, res.Diagnostics)
			}
		})
	}
}

func TestVerifyPoliciesContentsWithFixtures_StarterPacks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "starter_pack_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas(%s) failed: %v", schemaPath, err)
	}

	passDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass")
	failDir := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail")

	tests := []struct {
		name         string
		pack         string
		passFixtures []string
		failFixtures []string
	}{
		{
			name:         "AllPacks_WithFixtureDirectories",
			pack:         "all",
			passFixtures: []string{passDir},
			failFixtures: []string{failDir},
		},
		{
			name:         "AWSPack_WithAWSFixtures",
			pack:         "aws",
			passFixtures: []string{filepath.Join(passDir, "aws_pass.json")},
			failFixtures: []string{filepath.Join(failDir, "aws_fail.json")},
		},
		{
			name:         "AzurePack_WithAzureFixtures",
			pack:         "azure",
			passFixtures: []string{filepath.Join(passDir, "azure_pass.json")},
			failFixtures: []string{filepath.Join(failDir, "azure_fail.json")},
		},
		{
			name:         "GCPPack_WithGCPFixtures",
			pack:         "gcp",
			passFixtures: []string{filepath.Join(passDir, "gcp_pass.json")},
			failFixtures: []string{filepath.Join(failDir, "gcp_fail.json")},
		},
	}

	v := verifier.NewVerifier()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policies, err := policy.LoadPolicies(nil, []string{tc.pack})
			if err != nil {
				t.Fatalf("LoadPolicies(%q) failed: %v", tc.pack, err)
			}

			res, err := v.VerifyPoliciesContentsWithFixtures(ctx, policies, schemas, tc.passFixtures, tc.failFixtures)
			if err != nil {
				t.Fatalf("VerifyPoliciesContentsWithFixtures(%q) error: %v", tc.pack, err)
			}
			if !res.Valid || len(res.Diagnostics) != 0 {
				t.Errorf("pack %q failed fixture verification: Valid=%v, Diagnostics=%+v", tc.pack, res.Valid, res.Diagnostics)
			}
		})
	}

	t.Run("SwappedPassAndFailFixtures_ReportsFixtureDiagnostics", func(t *testing.T) {
		t.Parallel()

		awsPolicies, err := policy.LoadPolicies(nil, []string{"aws"})
		if err != nil {
			t.Fatalf("LoadPolicies(aws) failed: %v", err)
		}

		res, err := v.VerifyPoliciesContentsWithFixtures(
			ctx,
			awsPolicies,
			schemas,
			[]string{filepath.Join(failDir, "aws_fail.json")},
			[]string{filepath.Join(passDir, "aws_pass.json")},
		)
		if err != nil {
			t.Fatalf("VerifyPoliciesContentsWithFixtures returned operational error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected Valid == false when pass and fail fixtures are swapped")
		}

		var foundPass, foundFail bool
		for _, d := range res.Diagnostics {
			if d.ResourceType == "fixture:pass" {
				foundPass = true
			}
			if d.ResourceType == "fixture:fail" {
				foundFail = true
			}
		}
		if !foundPass || !foundFail {
			t.Errorf("expected both fixture:pass and fixture:fail diagnostics, got: %+v", res.Diagnostics)
		}
	})
}

func TestVerifyPolicyContents_InMemorySchemaAndMultiPackageDiagnostics(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "starter_pack_schema.json")
	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("LoadProviderSchemas failed: %v", err)
	}
	v := verifier.NewVerifier()

	t.Run("SingleValidInMemoryPolicy", func(t *testing.T) {
		t.Parallel()
		pc := model.PolicyContent{
			Path: "pack://memory/valid_ebs.rego",
			Content: []byte(`package tfsim.mem.ebs

import rego.v1

deny contains v if {
	some rc in input.resource_changes
	rc.type == "aws_ebs_volume"
	rc.change.after.encrypted == false
	v := {
		"rule_id": "mem-ebs",
		"severity": "HIGH",
		"message": "ebs not encrypted",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`),
		}
		res, err := v.VerifyPolicyContents(ctx, pc, schemas)
		if err != nil {
			t.Fatalf("VerifyPolicyContents failed: %v", err)
		}
		if !res.Valid || len(res.Diagnostics) != 0 {
			t.Errorf("expected Valid == true with 0 diagnostics, got: %+v", res)
		}
		if res.PolicyPath != pc.Path {
			t.Errorf("expected PolicyPath %q, got %q", pc.Path, res.PolicyPath)
		}
	})

	t.Run("MultiPackage_InvalidAttributeReportedWithLogicalPath", func(t *testing.T) {
		t.Parallel()
		goodPolicy := model.PolicyContent{
			Path: "pack://memory/good.rego",
			Content: []byte(`package tfsim.mem.good
import rego.v1
deny contains v if {
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	rc.change.after.enable_key_rotation == false
	v := {"rule_id": "ok", "severity": "HIGH", "message": "ok", "resource_address": rc.address, "resource_type": rc.type, "resource_name": rc.name}
}
`),
		}
		badPolicy := model.PolicyContent{
			Path: "pack://memory/bad.rego",
			Content: []byte(`package tfsim.mem.bad
import rego.v1
deny contains v if {
	some rc in input.resource_changes
	rc.type == "azurerm_key_vault"
	rc.change.after.nonexistent_kv_attr == false
	v := {"rule_id": "bad", "severity": "HIGH", "message": "bad", "resource_address": rc.address, "resource_type": rc.type, "resource_name": rc.name}
}
`),
		}

		res, err := v.VerifyPoliciesContents(ctx, []model.PolicyContent{goodPolicy, badPolicy}, schemas)
		if err != nil {
			t.Fatalf("VerifyPoliciesContents failed: %v", err)
		}
		if res.Valid {
			t.Fatal("expected Valid == false for invalid attribute in second package")
		}

		var found bool
		for _, d := range res.Diagnostics {
			if d.PolicyFile == badPolicy.Path && d.ResourceType == "azurerm_key_vault" && d.InvalidPath == "nonexistent_kv_attr" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected diagnostic on %q for azurerm_key_vault.nonexistent_kv_attr, got: %+v", badPolicy.Path, res.Diagnostics)
		}
	})

	t.Run("ErrorCases_EmptyPoliciesAndCanceledContext", func(t *testing.T) {
		t.Parallel()
		if _, err := v.VerifyPoliciesContents(ctx, nil, schemas); err == nil {
			t.Error("expected error for empty policies slice, got nil")
		}

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		pc := model.PolicyContent{Path: "pack://memory/x.rego", Content: []byte("package x\n")}
		if _, err := v.VerifyPolicyContents(canceledCtx, pc, schemas); !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}
