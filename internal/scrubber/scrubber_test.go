package scrubber_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/justr00t/tf-sim/internal/model"
	"github.com/justr00t/tf-sim/internal/parser"
	"github.com/justr00t/tf-sim/internal/scrubber"
)

// Compile-time interface check.
var _ model.PlanScrubber = (*scrubber.Scrubber)(nil)

func TestScrubStream_StripsTopLevelBloat(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "prior_state": {"format_version": "1.0", "values": {"root_module": {"resources": [{"values": {"secret": "prior-secret"}}]}}},
  "configuration": {"root_module": {"variables": {"db_pass": {"default": "cfg-secret"}}}},
  "variables": {"db_pass": {"value": "var-secret"}},
  "output_changes": {"db_conn": {"after": "postgres://u:p@host/db"}},
  "planned_values": {"root_module": {"resources": []}},
  "resource_drift": [{"address": "aws_s3_bucket.drift"}],
  "checks": [{"address": {"kind": "check"}}],
  "timestamp": "2026-11-20T00:00:00Z",
  "unknown_future_block": {"nested": [1, 2, 3]},
  "resource_changes": [
    {
      "address": "aws_s3_bucket.example",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "example",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {"bucket": "my-bucket"}
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.FormatVersion != "1.2" {
		t.Errorf("expected FormatVersion 1.2, got %q", summary.FormatVersion)
	}
	if summary.TerraformVersion != "1.9.0" {
		t.Errorf("expected TerraformVersion 1.9.0, got %q", summary.TerraformVersion)
	}
	if summary.ResourceChangesCount != 1 {
		t.Errorf("expected ResourceChangesCount 1, got %d", summary.ResourceChangesCount)
	}
	if summary.SkippedTopLevelFields != 9 {
		t.Errorf("expected SkippedTopLevelFields 9, got %d", summary.SkippedTopLevelFields)
	}

	var root map[string]any
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}

	if len(root) != 3 {
		t.Fatalf("expected exactly 3 top-level keys, got %d: %v", len(root), root)
	}
	for _, k := range []string{"format_version", "terraform_version", "resource_changes"} {
		if _, ok := root[k]; !ok {
			t.Errorf("expected top-level key %q to be present", k)
		}
	}
	for _, secret := range []string{"prior-secret", "cfg-secret", "var-secret"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("output leaked stripped top-level secret %q", secret)
		}
	}
}

func TestScrubStream_StripsChangeSideChannels(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "aws_db_instance.main",
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "main",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {"identifier": "prod-db"},
        "after_unknown": {"id": true},
        "before_sensitive": false,
        "after_sensitive": {"password": true},
        "replace_paths": [["identifier"]],
        "importing": {"id": "import-secret-id"},
        "before_identity": {"token": "identity-before-secret"},
        "after_identity": {"token": "identity-after-secret"},
        "generated_config": "resource \"aws_db_instance\" \"main\" {\n  password = \"hcl-generated-secret\"\n}"
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	for _, leaked := range []string{
		"hcl-generated-secret",
		"import-secret-id",
		"identity-before-secret",
		"identity-after-secret",
		"generated_config",
		"after_unknown",
		"before_sensitive",
		"after_sensitive",
		"replace_paths",
	} {
		if strings.Contains(out.String(), leaked) {
			t.Errorf("output must not contain side-channel field or secret %q", leaked)
		}
	}

	var root struct {
		ResourceChanges []struct {
			Change map[string]any `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(root.ResourceChanges) != 1 {
		t.Fatalf("expected 1 resource change, got %d", len(root.ResourceChanges))
	}
	ch := root.ResourceChanges[0].Change
	if len(ch) != 3 {
		t.Fatalf("expected change to have exactly 3 keys (actions, before, after), got %d: %v", len(ch), ch)
	}
	for _, k := range []string{"actions", "before", "after"} {
		if _, ok := ch[k]; !ok {
			t.Errorf("expected change key %q", k)
		}
	}
}

func TestScrubStream_SensitiveMasksPolymorphic(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_resource.polymorphic",
      "mode": "managed",
      "type": "example_resource",
      "name": "polymorphic",
      "change": {
        "actions": ["update"],
        "before": {
          "root_secret": "old-root-secret",
          "port": 5432
        },
        "before_sensitive": true,
        "after": {
          "nested_map": {
            "user": "alice",
            "pin": 9876,
            "enabled": true
          },
          "slice_items": [
            {"code": "s0", "public": "keep0"},
            "raw-secret-elem",
            "keep-elem"
          ],
          "tags": {
            "env": "prod",
            "owner": "platform"
          },
          "secrets": ["s1", "s2"]
        },
        "after_sensitive": {
          "nested_map": {
            "pin": true,
            "enabled": true
          },
          "slice_items": [
            {"code": true},
            true,
            false
          ],
          "tags": true,
          "secrets": true
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	// Expected redacted by mask:
	// before (root bool true): root_secret (1), port (1) = 2
	// after: nested_map.pin (1), nested_map.enabled (1), slice_items[0].code (1), slice_items[1] (1),
	//        tags.env (1), tags.owner (1), secrets[0] (1), secrets[1] (1) = 8
	// Total = 10
	if summary.RedactedByMaskCount != 10 {
		t.Errorf("expected RedactedByMaskCount == 10, got %d", summary.RedactedByMaskCount)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				Before map[string]any `json:"before"`
				After  map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	before := root.ResourceChanges[0].Change.Before
	if before["root_secret"] != scrubber.RedactedPlaceholder || before["port"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected root-level before_sensitive:true to redact all leaves, got %v", before)
	}

	after := root.ResourceChanges[0].Change.After
	nestedMap := after["nested_map"].(map[string]any)
	if nestedMap["user"] != "alice" {
		t.Errorf("expected nested_map.user preserved, got %v", nestedMap["user"])
	}
	if nestedMap["pin"] != scrubber.RedactedPlaceholder || nestedMap["enabled"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected nested_map.pin and enabled redacted, got %v", nestedMap)
	}

	sliceItems := after["slice_items"].([]any)
	if sliceItems[0].(map[string]any)["code"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected slice_items[0].code redacted")
	}
	if sliceItems[0].(map[string]any)["public"] != "keep0" {
		t.Errorf("expected slice_items[0].public preserved")
	}
	if sliceItems[1] != scrubber.RedactedPlaceholder || sliceItems[2] != "keep-elem" {
		t.Errorf("unexpected slice_items[1..2]: %v", sliceItems)
	}

	tags := after["tags"].(map[string]any)
	if tags["env"] != scrubber.RedactedPlaceholder || tags["owner"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected subtree tags:true to redact all tag leaves, got %v", tags)
	}

	secrets := after["secrets"].([]any)
	if secrets[0] != scrubber.RedactedPlaceholder || secrets[1] != scrubber.RedactedPlaceholder {
		t.Errorf("expected subtree secrets:true to redact all slice elements, got %v", secrets)
	}
}

func TestScrubStream_BuiltinKeyDenylist(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_secret.all",
      "mode": "managed",
      "type": "example_secret",
      "name": "all",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "password": "v1",
          "administrator_login_password": "v2",
          "master_password": "v3",
          "secret": "v4",
          "client_secret": "v5",
          "secret_string": "v6",
          "token": "v7",
          "auth_token": "v8",
          "access_token": "v9",
          "private_key": "v10",
          "ssh_private_key": "v11",
          "api_key": "v12",
          "x-api-key": "v13",
          "access_key": "v14",
          "primary_access_key": "v15",
          "secret_access_key": "v16",
          "connection_string": "v17",
          "primary_connection_string": "v18"
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.RedactedByKeyCount != 18 {
		t.Errorf("expected RedactedByKeyCount == 18, got %d", summary.RedactedByKeyCount)
	}
	if summary.TotalRedactedLeaves != 18 {
		t.Errorf("expected TotalRedactedLeaves == 18, got %d", summary.TotalRedactedLeaves)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for k, v := range root.ResourceChanges[0].Change.After {
		if v != scrubber.RedactedPlaceholder {
			t.Errorf("expected key %q to be redacted, got %v", k, v)
		}
	}
}

func TestScrubStream_TokenPatternsAndHighEntropy(t *testing.T) {
	ctx := context.Background()
	secrets := []string{
		"AKIA" + "IOSFODNN7EXAMPLE",
		"ASIA" + "IOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY",
		"ghp_" + "0123456789abcdef0123456789abcdef0123",
		"github_pat_" + "11AAAAAA00000000000000_0123456789abcdef0123456789abcdef",
		"glpat-" + "0123456789abcdef0123",
		"xoxb-" + "0000000000-0000000000-abcdefghijklmnopqrstuvwx",
		"AIza" + "SyDummyExampleKey0123456789abcdefghi",
		"sk_live_" + "0123456789abcdefghijklmnop",
		"sk-proj-" + "0123456789abcdefghijklmnopqrstuvwxyz",
		"-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----",
		"eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"postgres://admin:" + "examplePass123@db.example.internal:5432/prod",
		"DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + "abcd12345678;",
	}

	after := map[string]any{
		"user_data":   secrets[0],
		"description": secrets[1],
		"tags": map[string]any{
			"note0":  secrets[2],
			"note1":  secrets[3],
			"note2":  secrets[4],
			"note3":  secrets[5],
			"note4":  secrets[6],
			"note5":  secrets[7],
			"note6":  secrets[8],
			"note7":  secrets[9],
			"note8":  secrets[10],
			"note9":  secrets[11],
			"note10": secrets[12],
			"note11": secrets[13],
		},
	}

	plan := map[string]any{
		"format_version":    "1.2",
		"terraform_version": "1.9.0",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.app",
				"mode":    "managed",
				"type":    "aws_instance",
				"name":    "app",
				"change": map[string]any{
					"actions": []string{"create"},
					"before":  nil,
					"after":   after,
				},
			},
		},
	}

	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal input failed: %v", err)
	}

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, bytes.NewReader(raw), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.RedactedByValueCount != len(secrets) {
		t.Errorf("expected RedactedByValueCount == %d, got %d", len(secrets), summary.RedactedByValueCount)
	}

	outStr := out.String()
	for _, sec := range secrets {
		if strings.Contains(outStr, sec) {
			t.Errorf("output leaked secret substring %q", sec)
		}
	}
}

func TestScrubStream_CustomRedactKeyOverrides(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_app.web",
      "mode": "managed",
      "type": "example_app",
      "name": "web",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "custom_pii": "alice@example.com",
          "custom_flag": true,
          "x_internal_header": "header-val",
          "nested": {
            "Custom-PII": 999
          },
          "safe_attr": "keep"
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber(scrubber.WithRedactKeys("custom_pii", "X-Internal-Header", "custom_flag"))
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.RedactedByMaskCount != 4 {
		t.Errorf("expected custom redact keys to count as RedactedByMaskCount == 4, got %d", summary.RedactedByMaskCount)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	after := root.ResourceChanges[0].Change.After
	if after["custom_pii"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected custom_pii redacted, got %v", after["custom_pii"])
	}
	if after["custom_flag"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected custom_flag bool redacted under explicit key override, got %v", after["custom_flag"])
	}
	if after["x_internal_header"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected x_internal_header redacted, got %v", after["x_internal_header"])
	}
	if after["nested"].(map[string]any)["Custom-PII"] != scrubber.RedactedPlaceholder {
		t.Errorf("expected nested Custom-PII redacted, got %v", after["nested"])
	}
	if after["safe_attr"] != "keep" {
		t.Errorf("expected safe_attr preserved, got %v", after["safe_attr"])
	}
}

func TestScrubStream_StructuralAttributesPreserved(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.structural",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "structural",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012",
          "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012",
          "enable_key_rotation": true,
          "bucket_key_enabled": true,
          "default_kms_key_name": "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1",
          "http_tokens": "required",
          "shared_access_key_enabled": false,
          "manage_master_user_password": true,
          "automount_service_account_token": false,
          "minimum_password_length": 14,
          "azure_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
          "uuid": "12345678-1234-1234-1234-123456789012",
          "ami_id": "ami-0123456789abcdef0",
          "mode_enum": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
          "public_cert": "-----BEGIN CERTIFICATE-----\nMIIDtest\n-----END CERTIFICATE-----",
          "iam_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"iam:ChangePassword\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.TotalRedactedLeaves != 0 {
		t.Errorf("expected TotalRedactedLeaves == 0, got %d (out: %s)", summary.TotalRedactedLeaves, out.String())
	}
	if strings.Contains(out.String(), scrubber.RedactedPlaceholder) {
		t.Errorf("unexpected redaction placeholder in structural output: %s", out.String())
	}
}

func TestScrubStream_NullPreservation(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "azurerm_mssql_server.db",
      "mode": "managed",
      "type": "azurerm_mssql_server",
      "name": "db",
      "change": {
        "actions": ["delete"],
        "before": {
          "administrator_login_password": null,
          "secret_field": null
        },
        "before_sensitive": {
          "secret_field": true
        },
        "after": null,
        "after_sensitive": true
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.TotalRedactedLeaves != 0 {
		t.Errorf("expected TotalRedactedLeaves == 0 for null values, got %d", summary.TotalRedactedLeaves)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				Before map[string]any `json:"before"`
				After  any            `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	ch := root.ResourceChanges[0].Change
	if ch.After != nil {
		t.Errorf("expected after == nil, got %v", ch.After)
	}
	if val, ok := ch.Before["administrator_login_password"]; !ok || val != nil {
		t.Errorf("expected administrator_login_password == nil, got %v (present=%v)", val, ok)
	}
	if val, ok := ch.Before["secret_field"]; !ok || val != nil {
		t.Errorf("expected secret_field == nil, got %v (present=%v)", val, ok)
	}
}

func TestScrubStream_NumericPrecisionUseNumber(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_num.precision",
      "mode": "managed",
      "type": "example_num",
      "name": "precision",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "large_uint": 9007199254740993,
          "min_int64": -9223372036854775808,
          "small_dec": 0.0000000123456789
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	outStr := out.String()
	for _, exact := range []string{"9007199254740993", "-9223372036854775808", "0.0000000123456789"} {
		if !strings.Contains(outStr, exact) {
			t.Errorf("expected exact numeric literal %s in output, got:\n%s", exact, outStr)
		}
	}
}

func TestScrubStream_DeterministicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "prior_state": {"ignored": true},
  "resource_changes": [
    {
      "address": "aws_db_instance.db",
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "db",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "password": "my-secret-password",
          "tags": {"z": "1", "a": "2", "tok": "` + "AKIA" + `IOSFODNN7EXAMPLE"}
        },
        "after_sensitive": {"password": true}
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out1, out2, out3 bytes.Buffer

	if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out1); err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out2); err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
		t.Fatalf("scrub output is not deterministic:\nout1=%s\nout2=%s", out1.String(), out2.String())
	}

	summary3, err := s.ScrubStream(ctx, bytes.NewReader(out1.Bytes()), &out3)
	if err != nil {
		t.Fatalf("run 3 (idempotency) failed: %v", err)
	}
	if !bytes.Equal(out1.Bytes(), out3.Bytes()) {
		t.Fatalf("scrub output is not idempotent:\nout1=%s\nout3=%s", out1.String(), out3.String())
	}
	if summary3.TotalRedactedLeaves != 0 {
		t.Errorf("expected idempotent pass TotalRedactedLeaves == 0, got %d", summary3.TotalRedactedLeaves)
	}
}

func TestScrubStream_PreservesNoOpAndReadActions(t *testing.T) {
	ctx := context.Background()
	planPath := filepath.Join("..", "..", "testdata", "plans", "repo_payments_aws.json")

	p := parser.NewParser(parser.WithIncludeNoOp(true), parser.WithIncludeRead(true))
	rawSnap, err := p.ParsePlanFile(ctx, planPath, "payments-aws")
	if err != nil {
		t.Fatalf("ParsePlanFile(raw) failed: %v", err)
	}

	scrubbedPath := filepath.Join(t.TempDir(), "repo_payments_aws.json")
	s := scrubber.NewScrubber()
	if _, err := s.ScrubFile(ctx, planPath, scrubbedPath); err != nil {
		t.Fatalf("ScrubFile failed: %v", err)
	}

	scrubbedSnap, err := p.ParsePlanFile(ctx, scrubbedPath, "payments-aws")
	if err != nil {
		t.Fatalf("ParsePlanFile(scrubbed) failed: %v", err)
	}

	if len(scrubbedSnap.ResourceChanges) != 4 {
		t.Fatalf("expected 4 resource changes (2 create, 1 no-op, 1 read), got %d", len(scrubbedSnap.ResourceChanges))
	}
	if !reflect.DeepEqual(rawSnap.ResourceChanges, scrubbedSnap.ResourceChanges) {
		t.Errorf("resource changes mismatch after scrubbing:\nraw: %+v\nscrubbed: %+v", rawSnap.ResourceChanges, scrubbedSnap.ResourceChanges)
	}
}

func TestScrubStream_ReorderedAndMissingTopLevelKeys(t *testing.T) {
	ctx := context.Background()
	s := scrubber.NewScrubber()

	t.Run("ResourceChangesBeforeVersions", func(t *testing.T) {
		input := `{"resource_changes":[],"terraform_version":"1.9.0","format_version":"1.2"}`
		var out bytes.Buffer
		summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
		if err != nil {
			t.Fatalf("ScrubStream failed: %v", err)
		}
		if summary.FormatVersion != "1.2" || summary.TerraformVersion != "1.9.0" {
			t.Errorf("unexpected summary versions: %+v", summary)
		}
		var root map[string]any
		if err := json.Unmarshal(out.Bytes(), &root); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out.String())
		}
		if root["format_version"] != "1.2" || root["terraform_version"] != "1.9.0" {
			t.Errorf("versions missing from output: %v", root)
		}
	})

	t.Run("ResourceChangesOmitted", func(t *testing.T) {
		input := `{"format_version":"1.2","terraform_version":"1.9.0"}`
		var out bytes.Buffer
		if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
			t.Fatalf("ScrubStream failed: %v", err)
		}
		var root map[string]any
		if err := json.Unmarshal(out.Bytes(), &root); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		rc, ok := root["resource_changes"].([]any)
		if !ok || len(rc) != 0 {
			t.Errorf("expected empty resource_changes array, got %T %v", root["resource_changes"], root["resource_changes"])
		}
	})

	t.Run("ResourceChangesNull", func(t *testing.T) {
		input := `{"format_version":"1.2","resource_changes":null}`
		var out bytes.Buffer
		if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
			t.Fatalf("ScrubStream failed: %v", err)
		}
		var root map[string]any
		if err := json.Unmarshal(out.Bytes(), &root); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		rc, ok := root["resource_changes"].([]any)
		if !ok || len(rc) != 0 {
			t.Errorf("expected empty resource_changes array, got %T %v", root["resource_changes"], root["resource_changes"])
		}
	})

	t.Run("ResourceChangeWithNullChange", func(t *testing.T) {
		input := `{"format_version":"1.2","resource_changes":[{"address":"null_resource.x","mode":"managed","type":"null_resource","name":"x","change":null}]}`
		var out bytes.Buffer
		if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
			t.Fatalf("ScrubStream failed: %v", err)
		}
		var root map[string]any
		if err := json.Unmarshal(out.Bytes(), &root); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
	})
}

func TestScrubStream_MismatchedMaskShapes(t *testing.T) {
	ctx := context.Background()
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_res.mismatch",
      "mode": "managed",
      "type": "example_res",
      "name": "mismatch",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "short_mask": ["a", "b", "` + "AKIA" + `IOSFODNN7EXAMPLE"],
          "string_mask": ["x", "y"],
          "map_mask_on_slice": ["m0", "m1"],
          "slice_mask_on_map": {"password": "pw", "name": "ok"}
        },
        "after_sensitive": {
          "short_mask": [true],
          "string_mask": "unexpected",
          "map_mask_on_slice": {"0": true},
          "slice_mask_on_map": [true]
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	after := root.ResourceChanges[0].Change.After
	shortMask := after["short_mask"].([]any)
	if shortMask[0] != scrubber.RedactedPlaceholder || shortMask[1] != "b" || shortMask[2] != scrubber.RedactedPlaceholder {
		t.Errorf("unexpected short_mask result: %v", shortMask)
	}
	sliceMaskOnMap := after["slice_mask_on_map"].(map[string]any)
	if sliceMaskOnMap["password"] != scrubber.RedactedPlaceholder || sliceMaskOnMap["name"] != "ok" {
		t.Errorf("unexpected slice_mask_on_map result: %v", sliceMaskOnMap)
	}
}

func TestScrubFile_InPlaceSamePath(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	planPath := filepath.Join(tmpDir, "plan.json")
	raw := `{"format_version":"1.2","terraform_version":"1.9.0","prior_state":{"x":1},"resource_changes":[{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["create"],"before":null,"after":{"password":"secret"}}}]}`
	if err := os.WriteFile(planPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	s := scrubber.NewScrubber()
	summary, err := s.ScrubFile(ctx, planPath, planPath)
	if err != nil {
		t.Fatalf("in-place ScrubFile failed: %v", err)
	}
	if summary.RedactedByKeyCount != 1 || summary.SkippedTopLevelFields != 1 {
		t.Errorf("unexpected summary: %+v", summary)
	}

	updated, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read updated file failed: %v", err)
	}
	if strings.Contains(string(updated), "secret") || strings.Contains(string(updated), "prior_state") {
		t.Errorf("in-place scrubbed file still contains unsanitized data: %s", string(updated))
	}
}

func TestScrubReaderToFile_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "out.json")
	raw := `{"format_version":"1.2","terraform_version":"1.9.0","resource_changes":[{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["create"],"before":null,"after":{"token":"tok-val"}}}]}`

	s := scrubber.NewScrubber()
	summary, err := s.ScrubReaderToFile(ctx, strings.NewReader(raw), outPath)
	if err != nil {
		t.Fatalf("ScrubReaderToFile failed: %v", err)
	}
	if summary.RedactedByKeyCount != 1 {
		t.Errorf("expected RedactedByKeyCount == 1, got %d", summary.RedactedByKeyCount)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read outPath failed: %v", err)
	}
	if strings.Contains(string(b), "tok-val") {
		t.Errorf("output leaked token value")
	}
}

func TestScrubStream_LargePriorStateBoundedMemory(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	buf.WriteString(`{"format_version":"1.2","terraform_version":"1.9.0","prior_state":{"blobs":[`)
	chunk := `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	// ~5 MB prior_state array
	for i := 0; i < 50000; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(chunk)
	}
	buf.WriteString(`]},"resource_changes":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","change":{"actions":["create"],"before":null,"after":{"bucket":"ok"}}}]}`)

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, &buf, &out)
	if err != nil {
		t.Fatalf("ScrubStream failed on large prior_state: %v", err)
	}
	if summary.SkippedTopLevelFields != 1 || summary.ResourceChangesCount != 1 {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestScrubFile_MalformedJSONLeavesNoPartialOut(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	brokenPath := filepath.Join(tmpDir, "broken.json")
	outPath := filepath.Join(tmpDir, "scrubbed.json")
	if err := os.WriteFile(brokenPath, []byte(`{"format_version":"1.2","resource_changes":[{"address":`), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	s := scrubber.NewScrubber()
	if _, err := s.ScrubFile(ctx, brokenPath, outPath); err == nil {
		t.Fatalf("expected error on malformed JSON")
	}

	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("expected outPath not to exist after failure, got err=%v", err)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tf-sim-scrub-") {
			t.Errorf("leftover temp file found: %s", e.Name())
		}
	}
}

func TestScrubStream_NonObjectRootAndTrailingGarbage(t *testing.T) {
	ctx := context.Background()
	s := scrubber.NewScrubber()

	cases := []struct {
		name  string
		input string
	}{
		{"ArrayRoot", `["array"]`},
		{"PrimitiveRoot", `"primitive"`},
		{"TrailingObject", `{"format_version":"1.2"}{"extra":1}`},
		{"EmptyInput", ``},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := s.ScrubStream(ctx, strings.NewReader(tc.input), &out); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestScrubStream_DuplicateTopLevelKeys(t *testing.T) {
	ctx := context.Background()
	s := scrubber.NewScrubber()

	cases := []string{
		`{"terraform_version":"1.8.0","terraform_version":"1.9.0","resource_changes":[]}`,
		`{"format_version":"1.1","format_version":"1.2","resource_changes":[]}`,
		`{"resource_changes":[],"resource_changes":[]}`,
	}
	for _, input := range cases {
		var out bytes.Buffer
		if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err == nil {
			t.Errorf("expected duplicate top-level key error for %s", input)
		}
	}
}

func TestScrubStream_MaxRecursionDepthExceeded(t *testing.T) {
	ctx := context.Background()
	var sb strings.Builder
	sb.WriteString(`{"format_version":"1.2","resource_changes":[{"address":"a.b","mode":"managed","type":"a","name":"b","change":{"actions":["create"],"before":null,"after":`)
	for i := 0; i < 600; i++ {
		sb.WriteString(`{"n":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 600; i++ {
		sb.WriteByte('}')
	}
	sb.WriteString(`}}]}`)

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	_, err := s.ScrubStream(ctx, strings.NewReader(sb.String()), &out)
	if err == nil {
		t.Fatalf("expected max recursion depth error")
	}
	if !strings.Contains(err.Error(), "maximum JSON nesting depth") {
		t.Errorf("expected 'maximum JSON nesting depth' in error, got: %v", err)
	}
}

func TestScrubStream_ContextCanceled(t *testing.T) {
	s := scrubber.NewScrubber()

	t.Run("PreCanceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out bytes.Buffer
		_, err := s.ScrubStream(ctx, strings.NewReader(`{"format_version":"1.2"}`), &out)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("MidStreamCanceledDuringSkip", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var buf bytes.Buffer
		buf.WriteString(`{"format_version":"1.2","prior_state":[`)
		for i := 0; i < 5000; i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`1`)
		}
		buf.WriteString(`],"resource_changes":[]}`)

		// Cancel after initial bytes are read
		pr, pw := io.Pipe()
		defer pr.Close()
		go func() {
			data := buf.Bytes()
			_, _ = pw.Write(data[:2048])
			cancel()
			_, _ = pw.Write(data[2048:])
			_ = pw.Close()
		}()

		var out bytes.Buffer
		_, err := s.ScrubStream(ctx, pr, &out)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled mid-stream, got %v", err)
		}
	})
}

func TestScrubStream_ErrorsNeverLeakSecretValues(t *testing.T) {
	ctx := context.Background()
	secretVal := "super-secret-value-never-leak-12345"
	input := `{"format_version":"1.2","resource_changes":[{"address":"a.b","change":{"actions":["create"],"after":{"password":"` + secretVal + `"}}}, CORRUPT`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	_, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err == nil {
		t.Fatalf("expected error on malformed JSON")
	}
	if strings.Contains(err.Error(), secretVal) {
		t.Errorf("error message leaked secret value: %v", err)
	}
}

func TestScrubStream_M1_MalformedTokenErrorsNeverLeakSecrets(t *testing.T) {
	ctx := context.Background()
	s := scrubber.NewScrubber()

	rootSecret := "sk_live_" + "0123456789abcdefghijklmnop"
	rcSecret := "ghp_" + "0123456789abcdef0123456789abcdef0123"
	trailingSecret := "AIza" + "SyDummyExampleKey0123456789abcdefghi"

	cases := []struct {
		name   string
		input  string
		secret string
	}{
		{
			name:   "MalformedRootStringToken",
			input:  `"` + rootSecret + `"`,
			secret: rootSecret,
		},
		{
			name:   "MalformedResourceChangesStringToken",
			input:  `{"format_version":"1.2","resource_changes":"` + rcSecret + `"}`,
			secret: rcSecret,
		},
		{
			name:   "TrailingSecretTokenAfterRootObject",
			input:  `{"format_version":"1.2","resource_changes":[]}"` + trailingSecret + `"`,
			secret: trailingSecret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := s.ScrubStream(ctx, strings.NewReader(tc.input), &out)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if strings.Contains(err.Error(), tc.secret) {
				t.Errorf("error message leaked secret token: %v", err)
			}
		})
	}
}

func TestScrubStream_M2_ResourceChangeIndexValidationAndScrub(t *testing.T) {
	ctx := context.Background()
	s := scrubber.NewScrubber()

	t.Run("ValidScalarAndSecretStringIndex", func(t *testing.T) {
		secretIdx := "AKIA" + "IOSFODNN7EXAMPLE"
		input := `{
  "format_version": "1.2",
  "resource_changes": [
    {"address": "a.b[0]", "mode": "managed", "type": "a", "name": "b", "index": 0, "change": {"actions": ["create"], "before": null, "after": {"x": "ok"}}},
    {"address": "a.b[\"prod\"]", "mode": "managed", "type": "a", "name": "b", "index": "prod", "change": {"actions": ["create"], "before": null, "after": {"x": "ok"}}},
    {"address": "a.b", "mode": "managed", "type": "a", "name": "b", "index": null, "change": {"actions": ["create"], "before": null, "after": {"x": "ok"}}},
    {"address": "a.b[\"secret\"]", "mode": "managed", "type": "a", "name": "b", "index": "` + secretIdx + `", "change": {"actions": ["create"], "before": null, "after": {"x": "ok"}}}
  ]
}`
		var out bytes.Buffer
		summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
		if err != nil {
			t.Fatalf("ScrubStream failed: %v", err)
		}
		if summary.RedactedByValueCount != 1 {
			t.Errorf("expected RedactedByValueCount == 1 for secret index, got %d", summary.RedactedByValueCount)
		}
		if strings.Contains(out.String(), secretIdx) {
			t.Errorf("output leaked secret index: %s", out.String())
		}
	})

	t.Run("InvalidNonScalarIndexRejected", func(t *testing.T) {
		for _, badIdx := range []string{`{"k":"v"}`, `[1,2]`, `true`} {
			input := `{"format_version":"1.2","resource_changes":[{"address":"a.b","mode":"managed","type":"a","name":"b","index":` + badIdx + `,"change":{"actions":["create"],"before":null,"after":{}}}]}`
			var out bytes.Buffer
			if _, err := s.ScrubStream(ctx, strings.NewReader(input), &out); err == nil {
				t.Errorf("expected error for non-scalar index %s, got nil", badIdx)
			}
		}
	})
}

func TestScrubStream_M4_CamelCaseKeysAndHardening(t *testing.T) {
	ctx := context.Background()
	largeBlob := strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5-A6bC7dE8fG9hI0jK1lM2nO3p", 80) // 5120 bytes > 4096
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "example_app.hardening",
      "mode": "managed",
      "type": "example_app",
      "name": "hardening",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "adminPassword": "pw1",
          "clientSecret": "sec1",
          "apiKey": "key1",
          "accessToken": "tok1",
          "privateKey": "pk1",
          "connectionString": "cs1",
          "kmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012",
          "enableKeyRotation": true,
          "httpTokens": "required",
          "manageMasterUserPassword": true,
          "shortConn": "Server=db;Password=s3cr3t;",
          "bypassConn": "Server=db;Password=[REDACTED]extraSecret;",
          "largeBlob": "` + largeBlob + `",
          "authHeader": "Authorization: Basic ` + "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" + `"
        }
      }
    }
  ]
}`

	s := scrubber.NewScrubber()
	var out bytes.Buffer
	summary, err := s.ScrubStream(ctx, strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("ScrubStream failed: %v", err)
	}

	if summary.RedactedByKeyCount != 6 {
		t.Errorf("expected RedactedByKeyCount == 6, got %d", summary.RedactedByKeyCount)
	}
	if summary.RedactedByValueCount != 4 {
		t.Errorf("expected RedactedByValueCount == 4, got %d", summary.RedactedByValueCount)
	}

	var root struct {
		ResourceChanges []struct {
			Change struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(out.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	after := root.ResourceChanges[0].Change.After

	for _, k := range []string{"adminPassword", "clientSecret", "apiKey", "accessToken", "privateKey", "connectionString", "shortConn", "bypassConn", "largeBlob", "authHeader"} {
		if after[k] != scrubber.RedactedPlaceholder {
			t.Errorf("expected %q to be redacted, got %v", k, after[k])
		}
	}
	if after["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012" {
		t.Errorf("expected kmsKeyId preserved, got %v", after["kmsKeyId"])
	}
	if after["enableKeyRotation"] != true || after["httpTokens"] != "required" || after["manageMasterUserPassword"] != true {
		t.Errorf("expected camelCase structural attributes preserved, got %v", after)
	}
}
