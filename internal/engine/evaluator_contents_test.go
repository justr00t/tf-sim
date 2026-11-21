package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/engine"
	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/policy"
)

func TestEvaluatePlanContents_CacheKeyDistinguishesSamePathModifiedContent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	snapshot := &model.PlanSnapshot{
		SnapshotID: "snap-cache-content",
		RepoName:   "cache-repo",
		ResourceChanges: []model.ResourceChange{
			{
				Address:      "azurerm_storage_account.insecure",
				Type:         "azurerm_storage_account",
				Name:         "insecure",
				ProviderName: "registry.terraform.io/hashicorp/azurerm",
				Actions:      []string{"create"},
				After: map[string]any{
					"name":                       "insecure01",
					"https_traffic_only_enabled": false,
				},
			},
		},
	}

	const logicalPath = "pack://virtual/dynamic_rule.rego"
	v1Policy := `package tfsim.cachetest

import rego.v1

deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.https_traffic_only_enabled == false
	violation := {
		"rule_id": "CACHE-CONTENT-V1",
		"severity": "HIGH",
		"message": "v1 violation",
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
`
	v2Policy := strings.ReplaceAll(v1Policy, "CACHE-CONTENT-V1", "CACHE-CONTENT-V2")

	eval := engine.NewEvaluator()

	res1, err := eval.EvaluatePlanContents(ctx, []model.PolicyContent{
		{Path: logicalPath, Content: []byte(v1Policy)},
	}, snapshot)
	if err != nil {
		t.Fatalf("first EvaluatePlanContents failed: %v", err)
	}
	if len(res1.Violations) != 1 || res1.Violations[0].RuleID != "CACHE-CONTENT-V1" {
		t.Fatalf("expected violation CACHE-CONTENT-V1, got: %+v", res1.Violations)
	}

	// Same Path, modified Content: MUST NOT return stale cached V1 result.
	res2, err := eval.EvaluatePlanContents(ctx, []model.PolicyContent{
		{Path: logicalPath, Content: []byte(v2Policy)},
	}, snapshot)
	if err != nil {
		t.Fatalf("second EvaluatePlanContents failed: %v", err)
	}
	if len(res2.Violations) != 1 || res2.Violations[0].RuleID != "CACHE-CONTENT-V2" {
		t.Fatalf("stale cache hit! expected violation CACHE-CONTENT-V2 for modified content at same path, got: %+v", res2.Violations)
	}
}

func TestEvaluatePlanContents_MultiPackageDiscovery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	snapshot := &model.PlanSnapshot{
		SnapshotID: "snap-multipkg",
		RepoName:   "multipkg-repo",
		ResourceChanges: []model.ResourceChange{
			{
				Address:      "aws_ebs_volume.unencrypted",
				Type:         "aws_ebs_volume",
				Name:         "unencrypted",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Actions:      []string{"create"},
				After:        map[string]any{"encrypted": false},
			},
			{
				Address:      "azurerm_storage_account.insecure",
				Type:         "azurerm_storage_account",
				Name:         "insecure",
				ProviderName: "registry.terraform.io/hashicorp/azurerm",
				Actions:      []string{"create"},
				After:        map[string]any{"https_traffic_only_enabled": false},
			},
			{
				Address:      "google_storage_bucket.open",
				Type:         "google_storage_bucket",
				Name:         "open",
				ProviderName: "registry.terraform.io/hashicorp/google",
				Actions:      []string{"create"},
				After:        map[string]any{"uniform_bucket_level_access": false},
			},
		},
	}

	policies := []model.PolicyContent{
		{
			Path: "pack://custom/pkg_one.rego",
			Content: []byte(`package tfsim.custom.one
import rego.v1
deny contains v if {
	some rc in input.resource_changes
	rc.type == "aws_ebs_volume"
	rc.change.after.encrypted == false
	v := {"rule_id": "PKG-ONE", "severity": "HIGH", "message": "pkg one", "resource_address": rc.address, "resource_type": rc.type, "resource_name": rc.name}
}
`),
		},
		{
			Path: "pack://custom/pkg_two.rego",
			Content: []byte(`package tfsim.custom.two
import rego.v1
violation contains v if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.https_traffic_only_enabled == false
	v := {"rule_id": "PKG-TWO", "severity": "HIGH", "message": "pkg two", "resource_address": rc.address, "resource_type": rc.type, "resource_name": rc.name}
}
`),
		},
		{
			Path: "pack://custom/pkg_three.rego",
			Content: []byte(`package tfsim.custom.three
import rego.v1
deny contains v if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	rc.change.after.uniform_bucket_level_access == false
	v := {"rule_id": "PKG-THREE", "severity": "MEDIUM", "message": "pkg three", "resource_address": rc.address, "resource_type": rc.type, "resource_name": rc.name}
}
`),
		},
	}

	eval := engine.NewEvaluator()
	res, err := eval.EvaluatePlanContents(ctx, policies, snapshot)
	if err != nil {
		t.Fatalf("EvaluatePlanContents multi-package failed: %v", err)
	}
	if res.Passed {
		t.Fatalf("expected Passed == false, got true")
	}
	if len(res.Violations) != 3 {
		t.Fatalf("expected 3 violations across 3 distinct packages, got %d: %+v", len(res.Violations), res.Violations)
	}

	gotRules := map[string]bool{}
	for _, v := range res.Violations {
		gotRules[v.RuleID] = true
	}
	for _, want := range []string{"PKG-ONE", "PKG-TWO", "PKG-THREE"} {
		if !gotRules[want] {
			t.Errorf("missing expected rule %q from multi-package evaluation; got %+v", want, res.Violations)
		}
	}
}

func TestEvaluatePlanContents_ValidationAndZeroValue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	policies, err := policy.LoadPolicies(nil, []string{"aws"})
	if err != nil {
		t.Fatalf("LoadPolicies(aws) failed: %v", err)
	}

	snap := &model.PlanSnapshot{
		SnapshotID: "snap-valid",
		RepoName:   "valid-repo",
		ResourceChanges: []model.ResourceChange{
			{
				Address:      "aws_ebs_volume.bad",
				Type:         "aws_ebs_volume",
				Name:         "bad",
				ProviderName: "registry.terraform.io/hashicorp/aws",
				Actions:      []string{"create"},
				After:        map[string]any{"encrypted": false},
			},
		},
	}

	t.Run("EmptyPoliciesError", func(t *testing.T) {
		t.Parallel()
		eval := engine.NewEvaluator()
		if _, err := eval.EvaluatePlanContents(ctx, nil, snap); err == nil {
			t.Fatal("expected error for empty policies, got nil")
		}
	})

	t.Run("NilSnapshotError", func(t *testing.T) {
		t.Parallel()
		eval := engine.NewEvaluator()
		if _, err := eval.EvaluatePlanContents(ctx, policies, nil); err == nil {
			t.Fatal("expected error for nil snapshot, got nil")
		}
	})

	t.Run("CanceledContextError", func(t *testing.T) {
		t.Parallel()
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		eval := engine.NewEvaluator()
		_, err := eval.EvaluatePlanContents(canceledCtx, policies, snap)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("ZeroValueEvaluatorWorks", func(t *testing.T) {
		t.Parallel()
		eval := &engine.Evaluator{}
		res, err := eval.EvaluatePlanContents(ctx, policies, snap)
		if err != nil {
			t.Fatalf("zero-value EvaluatePlanContents failed: %v", err)
		}
		if res.Passed || len(res.Violations) != 1 || res.Violations[0].RuleID != "aws-ebs-encrypt" {
			t.Fatalf("unexpected zero-value evaluation result: %+v", res)
		}
	})
}

func TestEvaluatePlanContents_StarterPackAll28RulesAndRemediationSpecs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	p := parser.NewParser()
	eval := engine.NewEvaluator()

	allPolicies, err := policy.LoadPolicies(nil, []string{"all"})
	if err != nil {
		t.Fatalf("LoadPolicies(all) failed: %v", err)
	}

	// 1. Verify all 3 compliant pass fixtures produce 0 violations.
	for _, file := range []string{"aws_pass.json", "azure_pass.json", "gcp_pass.json"} {
		t.Run("PassFixture_"+file, func(t *testing.T) {
			t.Parallel()
			planPath := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "pass", file)
			snap, err := p.ParsePlanFile(ctx, planPath, file)
			if err != nil {
				t.Fatalf("ParsePlanFile(%s) failed: %v", planPath, err)
			}
			res, err := eval.EvaluatePlanContents(ctx, allPolicies, snap)
			if err != nil {
				t.Fatalf("EvaluatePlanContents(%s) failed: %v", file, err)
			}
			if !res.Passed || len(res.Violations) != 0 {
				t.Errorf("expected 0 violations on %s, got %d: %+v", file, len(res.Violations), res.Violations)
			}
		})
	}

	// 2. Verify all 28 rules on fail fixtures (both explicit_bad and missing_attrs),
	//    exact remediation metadata on 26 patchable rules, nil remediation on 2 non-patchable rules,
	//    and 0 violations on deleted_bad resources.
	type ruleExpectation struct {
		ruleID       string
		resourceType string
		patchable    bool
		attrPath     []string
		suggestedVal any
	}

	catalog := map[string][]ruleExpectation{
		"aws_fail.json": {
			{"aws-s3-pab-acls", "aws_s3_bucket_public_access_block", true, []string{"block_public_acls"}, true},
			{"aws-s3-pab-policy", "aws_s3_bucket_public_access_block", true, []string{"block_public_policy"}, true},
			{"aws-s3-pab-ignore", "aws_s3_bucket_public_access_block", true, []string{"ignore_public_acls"}, true},
			{"aws-s3-pab-restrict", "aws_s3_bucket_public_access_block", true, []string{"restrict_public_buckets"}, true},
			{"aws-s3-sse-kms", "aws_s3_bucket_server_side_encryption_configuration", true, []string{"rule", "apply_server_side_encryption_by_default", "sse_algorithm"}, "aws:kms"},
			{"aws-s3-versioning", "aws_s3_bucket_versioning", true, []string{"versioning_configuration", "status"}, "Enabled"},
			{"aws-rds-encrypt", "aws_db_instance", true, []string{"storage_encrypted"}, true},
			{"aws-rds-public", "aws_db_instance", true, []string{"publicly_accessible"}, false},
			{"aws-rds-iam-auth", "aws_db_instance", true, []string{"iam_database_authentication_enabled"}, true},
			{"aws-ebs-encrypt", "aws_ebs_volume", true, []string{"encrypted"}, true},
			{"aws-ec2-ebs-opt", "aws_instance", true, []string{"ebs_optimized"}, true},
			{"aws-kms-rotation", "aws_kms_key", true, []string{"enable_key_rotation"}, true},
		},
		"azure_fail.json": {
			{"azure-storage-https", "azurerm_storage_account", true, []string{"https_traffic_only_enabled"}, true},
			{"azure-storage-tls", "azurerm_storage_account", true, []string{"min_tls_version"}, "TLS1_2"},
			{"azure-mssql-tls", "azurerm_mssql_server", true, []string{"minimum_tls_version"}, "1.2"},
			{"azure-psql-flex-public", "azurerm_postgresql_flexible_server", true, []string{"public_network_access_enabled"}, false},
			{"azure-psql-flex-backup", "azurerm_postgresql_flexible_server", true, []string{"backup_retention_days"}, 7},
			{"azure-kv-softdel", "azurerm_key_vault", true, []string{"soft_delete_retention_days"}, 90},
			{"azure-kv-purge", "azurerm_key_vault", true, []string{"purge_protection_enabled"}, true},
			{"azure-kv-rbac", "azurerm_key_vault", true, []string{"enable_rbac_authorization"}, true},
		},
		"gcp_fail.json": {
			{"gcp-storage-ubla", "google_storage_bucket", true, []string{"uniform_bucket_level_access"}, true},
			{"gcp-storage-public", "google_storage_bucket", true, []string{"public_access_prevention"}, "enforced"},
			{"gcp-sql-ssl", "google_sql_database_instance", false, nil, nil},
			{"gcp-sql-backup", "google_sql_database_instance", false, nil, nil},
			{"gcp-compute-shielded", "google_compute_instance", true, []string{"shielded_instance_config", "enable_secure_boot"}, true},
			{"gcp-compute-ip-fwd", "google_compute_instance", true, []string{"can_ip_forward"}, false},
			{"gcp-kms-rotation", "google_kms_crypto_key", true, []string{"rotation_period"}, "7776000s"},
			{"gcp-firewall-log", "google_compute_firewall", true, []string{"log_config", "metadata"}, "INCLUDE_ALL_METADATA"},
		},
	}

	for file, rules := range catalog {
		t.Run("FailFixture_"+file, func(t *testing.T) {
			t.Parallel()
			planPath := filepath.Join("..", "..", "testdata", "starter_pack_fixtures", "fail", file)
			snap, err := p.ParsePlanFile(ctx, planPath, file)
			if err != nil {
				t.Fatalf("ParsePlanFile(%s) failed: %v", planPath, err)
			}
			res, err := eval.EvaluatePlanContents(ctx, allPolicies, snap)
			if err != nil {
				t.Fatalf("EvaluatePlanContents(%s) failed: %v", file, err)
			}
			if res.Passed {
				t.Fatalf("expected Passed == false on %s", file)
			}

			// Index violations by (rule_id, resource_address).
			type key struct {
				ruleID string
				addr   string
			}
			byKey := make(map[key]model.PolicyViolation, len(res.Violations))
			for _, v := range res.Violations {
				if strings.Contains(v.ResourceAddress, "deleted_") {
					t.Errorf("delete-only resource %q falsely triggered rule %q", v.ResourceAddress, v.RuleID)
				}
				if v.Severity == "" || v.Message == "" {
					t.Errorf("violation %q on %q missing severity or message: %+v", v.RuleID, v.ResourceAddress, v)
				}
				byKey[key{ruleID: v.RuleID, addr: v.ResourceAddress}] = v
			}

			for _, r := range rules {
				for _, suffix := range []string{"explicit_bad", "missing_attrs"} {
					addr := r.resourceType + "." + suffix
					v, ok := byKey[key{ruleID: r.ruleID, addr: addr}]
					if !ok {
						t.Errorf("rule %q did not fire on %s (%s)", r.ruleID, addr, file)
						continue
					}
					if v.ResourceType != r.resourceType {
						t.Errorf("rule %q ResourceType = %q, want %q", r.ruleID, v.ResourceType, r.resourceType)
					}
					if v.ResourceName != suffix {
						t.Errorf("rule %q ResourceName = %q, want %q", r.ruleID, v.ResourceName, suffix)
					}

					if r.patchable {
						if v.Remediation == nil {
							t.Errorf("patchable rule %q on %s has nil Remediation", r.ruleID, addr)
							continue
						}
						if !reflect.DeepEqual(v.Remediation.AttributePath, r.attrPath) {
							t.Errorf("rule %q AttributePath = %v, want %v", r.ruleID, v.Remediation.AttributePath, r.attrPath)
						}
						if !suggestedValuesEqual(v.Remediation.SuggestedVal, r.suggestedVal) {
							t.Errorf("rule %q SuggestedVal = %#v (%T), want %#v (%T)", r.ruleID, v.Remediation.SuggestedVal, v.Remediation.SuggestedVal, r.suggestedVal, r.suggestedVal)
						}
					} else {
						if v.Remediation != nil {
							t.Errorf("non-patchable rule %q on %s should omit remediation block, got %+v", r.ruleID, addr, v.Remediation)
						}
					}
				}
			}
		})
	}

	// 3. Verify replace actions (["delete", "create"] and ["create", "delete"]) and update actions DO trigger violations.
	t.Run("ReplaceAndUpdateActionsStillTriggerStarterPack", func(t *testing.T) {
		t.Parallel()
		replaceSnap := &model.PlanSnapshot{
			SnapshotID: "snap-replace",
			RepoName:   "replace-repo",
			ResourceChanges: []model.ResourceChange{
				{
					Address:      "aws_ebs_volume.replaced",
					Type:         "aws_ebs_volume",
					Name:         "replaced",
					ProviderName: "registry.terraform.io/hashicorp/aws",
					Actions:      []string{"delete", "create"},
					After:        map[string]any{"encrypted": false},
				},
				{
					Address:      "google_kms_crypto_key.replaced_cbd",
					Type:         "google_kms_crypto_key",
					Name:         "replaced_cbd",
					ProviderName: "registry.terraform.io/hashicorp/google",
					Actions:      []string{"create", "delete"},
					After:        map[string]any{"name": "key"},
				},
				{
					Address:      "azurerm_mssql_server.updated_bad",
					Type:         "azurerm_mssql_server",
					Name:         "updated_bad",
					ProviderName: "registry.terraform.io/hashicorp/azurerm",
					Actions:      []string{"update"},
					After:        map[string]any{"minimum_tls_version": "1.1"},
				},
			},
		}
		res, err := eval.EvaluatePlanContents(ctx, allPolicies, replaceSnap)
		if err != nil {
			t.Fatalf("EvaluatePlanContents(replace/update) failed: %v", err)
		}
		if len(res.Violations) != 3 {
			t.Fatalf("expected 3 violations for replace/update actions, got %d: %+v", len(res.Violations), res.Violations)
		}
	})

	// 4. Verify numeric threshold boundaries (backup_retention_days >= 7, soft_delete_retention_days >= 90).
	t.Run("NumericThresholdBoundaries", func(t *testing.T) {
		t.Parallel()
		boundarySnap := &model.PlanSnapshot{
			SnapshotID: "snap-boundaries",
			RepoName:   "boundary-repo",
			ResourceChanges: []model.ResourceChange{
				{
					Address:      "azurerm_postgresql_flexible_server.below_min",
					Type:         "azurerm_postgresql_flexible_server",
					Name:         "below_min",
					ProviderName: "registry.terraform.io/hashicorp/azurerm",
					Actions:      []string{"create"},
					After: map[string]any{
						"public_network_access_enabled": false,
						"backup_retention_days":         6,
					},
				},
				{
					Address:      "azurerm_postgresql_flexible_server.above_min",
					Type:         "azurerm_postgresql_flexible_server",
					Name:         "above_min",
					ProviderName: "registry.terraform.io/hashicorp/azurerm",
					Actions:      []string{"create"},
					After: map[string]any{
						"public_network_access_enabled": false,
						"backup_retention_days":         14,
					},
				},
				{
					Address:      "azurerm_key_vault.below_min",
					Type:         "azurerm_key_vault",
					Name:         "below_min",
					ProviderName: "registry.terraform.io/hashicorp/azurerm",
					Actions:      []string{"create"},
					After: map[string]any{
						"soft_delete_retention_days": 89,
						"purge_protection_enabled":   true,
						"enable_rbac_authorization":  true,
					},
				},
			},
		}
		res, err := eval.EvaluatePlanContents(ctx, allPolicies, boundarySnap)
		if err != nil {
			t.Fatalf("EvaluatePlanContents(boundaries) failed: %v", err)
		}
		if len(res.Violations) != 2 {
			t.Fatalf("expected exactly 2 boundary violations (backup=6 and soft_delete=89), got %d: %+v", len(res.Violations), res.Violations)
		}
		got := map[string]string{}
		for _, v := range res.Violations {
			got[v.RuleID] = v.ResourceAddress
		}
		if got["azure-psql-flex-backup"] != "azurerm_postgresql_flexible_server.below_min" {
			t.Errorf("expected azure-psql-flex-backup on below_min, got %+v", got)
		}
		if got["azure-kv-softdel"] != "azurerm_key_vault.below_min" {
			t.Errorf("expected azure-kv-softdel on below_min, got %+v", got)
		}
	})
}

func suggestedValuesEqual(got, want any) bool {
	if reflect.DeepEqual(got, want) {
		return true
	}
	gotNum, gotIsNum := toFloat64(got)
	wantNum, wantIsNum := toFloat64(want)
	if gotIsNum && wantIsNum {
		return gotNum == wantNum
	}
	return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want) && reflect.TypeOf(got) == reflect.TypeOf(want)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := strconv.ParseFloat(n.String(), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func TestEvaluator_CacheBoundingAndLRUEviction(t *testing.T) {
	ctx := context.Background()
	dummySnapshot := &model.PlanSnapshot{
		SnapshotID: "test-snap",
		RepoName:   "test-repo",
		SourcePath: "test.json",
		ResourceChanges: []model.ResourceChange{
			{
				Address: "aws_s3_bucket.test",
				Type:    "aws_s3_bucket",
				Actions: []string{"create"},
				After:   map[string]any{"bucket": "test-b"},
			},
		},
	}

	t.Run("ConfiguredMaxEntries_BoundedAndLRU", func(t *testing.T) {
		eval := engine.NewEvaluator()
		eval.SetMaxCacheEntries(3)

		// Generate 5 distinct policies
		for i := 1; i <= 5; i++ {
			p := []model.PolicyContent{
				{
					Path: fmt.Sprintf("policy_%d.rego", i),
					Content: []byte(fmt.Sprintf(`package tfsim.test
import rego.v1
# Variation %d
deny contains violation if {
	false
	violation := {"rule_id": "test", "resource_address": "none"}
}
`, i)),
				},
			}
			res, err := eval.EvaluatePlanContents(ctx, p, dummySnapshot)
			if err != nil {
				t.Fatalf("EvaluatePlanContents failed on iteration %d: %v", i, err)
			}
			if res == nil {
				t.Fatalf("expected non-nil result on iteration %d", i)
			}
			if eval.CacheLen() > 3 {
				t.Fatalf("expected cache size <= 3, got %d", eval.CacheLen())
			}
		}

		if eval.CacheLen() != 3 {
			t.Fatalf("expected cache size == 3, got %d", eval.CacheLen())
		}

		// Re-evaluating policy_4 should promote it to MRU
		p4 := []model.PolicyContent{
			{
				Path: "policy_4.rego",
				Content: []byte(`package tfsim.test
import rego.v1
# Variation 4
deny contains violation if {
	false
	violation := {"rule_id": "test", "resource_address": "none"}
}
`),
			},
		}
		if _, err := eval.EvaluatePlanContents(ctx, p4, dummySnapshot); err != nil {
			t.Fatalf("EvaluatePlanContents failed on p4: %v", err)
		}

		// Add policy 6 - should evict the LRU entry (policy_3)
		p6 := []model.PolicyContent{
			{
				Path: "policy_6.rego",
				Content: []byte(`package tfsim.test
import rego.v1
# Variation 6
deny contains violation if {
	false
	violation := {"rule_id": "test", "resource_address": "none"}
}
`),
			},
		}
		if _, err := eval.EvaluatePlanContents(ctx, p6, dummySnapshot); err != nil {
			t.Fatalf("EvaluatePlanContents failed on p6: %v", err)
		}

		if eval.CacheLen() != 3 {
			t.Fatalf("expected cache size == 3 after eviction, got %d", eval.CacheLen())
		}
	})

	t.Run("DefaultMaxEntries_BoundedAt64OnZeroValue", func(t *testing.T) {
		// Test zero-value &Evaluator{} with default limit (64)
		eval := &engine.Evaluator{}

		for i := 1; i <= 70; i++ {
			p := []model.PolicyContent{
				{
					Path: fmt.Sprintf("policy_%d.rego", i),
					Content: []byte(fmt.Sprintf(`package tfsim.test
import rego.v1
# Comment %d
deny contains violation if {
	false
	violation := {"rule_id": "test", "resource_address": "none"}
}
`, i)),
				},
			}
			_, err := eval.EvaluatePlanContents(ctx, p, dummySnapshot)
			if err != nil {
				t.Fatalf("EvaluatePlanContents failed on %d: %v", i, err)
			}
			if eval.CacheLen() > 64 {
				t.Fatalf("cache size exceeded maxCacheEntries (64): got %d", eval.CacheLen())
			}
		}

		if eval.CacheLen() != 64 {
			t.Fatalf("expected cache size == 64 after 70 unique policies, got %d", eval.CacheLen())
		}
	})
}
