package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/justr00t/tf-sim/internal/model"
)

func TestCLI_Remediate_StarterPack_All28Rules_ModulesCountForEachAndExternal(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create multi-file .tf tree:
	// - root main.tf: AWS root + count + for_each + GCP Cloud SQL advisory + external module + var.* resource
	// - ./modules/azure_sec/main.tf: all 8 Azure starter rules
	// - ./modules/gcp_app/main.tf -> ../shared_gcp (sibling module): 6 patchable GCP rules
	if err := os.MkdirAll(filepath.Join(tmpDir, "modules", "azure_sec"), 0o755); err != nil {
		t.Fatalf("mkdir azure_sec: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "modules", "gcp_app"), 0o755); err != nil {
		t.Fatalf("mkdir gcp_app: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "modules", "shared_gcp"), 0o755); err != nil {
		t.Fatalf("mkdir shared_gcp: %v", err)
	}

	rootTF := `variable "enable_ebs" {
  type    = bool
  default = false
}

module "azure_sec" {
  source = "./modules/azure_sec"
}

module "gcp_app" {
  source = "./modules/gcp_app"
}

module "ext_s3" {
  source = "terraform-aws-modules/s3-bucket/aws"
}

resource "aws_s3_bucket_public_access_block" "fe_pab" {
  for_each                = toset(["us-east-1.prod"])
  bucket                  = "fe-pab-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "root_sse" {
  bucket = "root-sse-bucket"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "root_ver" {
  bucket = "root-ver-bucket"
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_db_instance" "root_db" {
  identifier                          = "root-db"
  storage_encrypted                   = false
  publicly_accessible                 = true
  iam_database_authentication_enabled = false
}

resource "aws_ebs_volume" "count_vol" {
  count             = 2
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_ebs_volume" "var_driven" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.enable_ebs
}

resource "aws_instance" "root_ec2" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  ebs_optimized = false
}

resource "aws_kms_key" "root_kms" {
  description         = "root key"
  enable_key_rotation = false
}

resource "google_sql_database_instance" "advisory_sql" {
  name             = "advisory-cloudsql"
  database_version = "POSTGRES_15"
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }
    backup_configuration {
      enabled = false
    }
  }
}
`
	azureTF := `resource "azurerm_storage_account" "bad" {
  name                       = "badstorage01"
  https_traffic_only_enabled = false
  min_tls_version            = "TLS1_0"
}

resource "azurerm_mssql_server" "bad" {
  name                = "bad-mssql-srv"
  minimum_tls_version = "1.0"
}

resource "azurerm_postgresql_flexible_server" "bad" {
  name                          = "bad-psql-flex"
  public_network_access_enabled = true
  backup_retention_days         = 3
}

resource "azurerm_key_vault" "bad" {
  name                       = "bad-kv-01"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = false
}
`
	gcpAppTF := `module "shared_gcp" {
  source = "../shared_gcp"
}
`
	sharedGCPTF := `resource "google_storage_bucket" "bad" {
  name                        = "bad-gcs-bucket"
  location                    = "US"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

resource "google_compute_instance" "bad" {
  name           = "bad-vm"
  machine_type   = "e2-medium"
  zone           = "us-central1-a"
  can_ip_forward = true
  shielded_instance_config {
    enable_secure_boot = false
  }
}

resource "google_kms_crypto_key" "bad" {
  name            = "bad-crypto-key"
  key_ring        = "projects/demo/locations/global/keyRings/main"
  rotation_period = ""
}

resource "google_compute_firewall" "bad" {
  name    = "bad-firewall"
  network = "default"
  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}
`

	rootTFPath := filepath.Join(tmpDir, "main.tf")
	azureTFPath := filepath.Join(tmpDir, "modules", "azure_sec", "main.tf")
	sharedGCPTFPath := filepath.Join(tmpDir, "modules", "shared_gcp", "main.tf")

	if err := os.WriteFile(rootTFPath, []byte(rootTF), 0o600); err != nil {
		t.Fatalf("write root main.tf: %v", err)
	}
	if err := os.WriteFile(azureTFPath, []byte(azureTF), 0o600); err != nil {
		t.Fatalf("write azure main.tf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "modules", "gcp_app", "main.tf"), []byte(gcpAppTF), 0o600); err != nil {
		t.Fatalf("write gcp_app main.tf: %v", err)
	}
	if err := os.WriteFile(sharedGCPTFPath, []byte(sharedGCPTF), 0o600); err != nil {
		t.Fatalf("write shared_gcp main.tf: %v", err)
	}

	plan := map[string]any{
		"format_version":    "1.2",
		"terraform_version": "1.9.0",
		"planned_values":    map[string]any{"root_module": map[string]any{"resources": []any{}}},
		"resource_changes": []map[string]any{
			{
				"address": `aws_s3_bucket_public_access_block.fe_pab["us-east-1.prod"]`,
				"mode":    "managed",
				"type":    "aws_s3_bucket_public_access_block",
				"name":    "fe_pab",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"bucket":                  "fe-pab-bucket",
						"block_public_acls":       false,
						"block_public_policy":     false,
						"ignore_public_acls":      false,
						"restrict_public_buckets": false,
					},
				},
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.root_sse",
				"mode":    "managed",
				"type":    "aws_s3_bucket_server_side_encryption_configuration",
				"name":    "root_sse",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"bucket": "root-sse-bucket",
						"rule": []any{map[string]any{
							"apply_server_side_encryption_by_default": []any{map[string]any{"sse_algorithm": "AES256"}},
						}},
					},
				},
			},
			{
				"address": "aws_s3_bucket_versioning.root_ver",
				"mode":    "managed",
				"type":    "aws_s3_bucket_versioning",
				"name":    "root_ver",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"bucket":                   "root-ver-bucket",
						"versioning_configuration": []any{map[string]any{"status": "Disabled"}},
					},
				},
			},
			{
				"address": "aws_db_instance.root_db",
				"mode":    "managed",
				"type":    "aws_db_instance",
				"name":    "root_db",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"identifier":                          "root-db",
						"storage_encrypted":                   false,
						"publicly_accessible":                 true,
						"iam_database_authentication_enabled": false,
					},
				},
			},
			{
				"address": "aws_ebs_volume.count_vol[0]",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "count_vol",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
			{
				"address": "aws_ebs_volume.count_vol[1]",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "count_vol",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
			{
				"address": "aws_ebs_volume.var_driven",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "var_driven",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
			{
				"address": "aws_instance.root_ec2",
				"mode":    "managed",
				"type":    "aws_instance",
				"name":    "root_ec2",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"ebs_optimized": false},
				},
			},
			{
				"address": "aws_kms_key.root_kms",
				"mode":    "managed",
				"type":    "aws_kms_key",
				"name":    "root_kms",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"enable_key_rotation": false},
				},
			},
			{
				"address": "module.ext_s3.aws_ebs_volume.ext_vol",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "ext_vol",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
			{
				"address": "module.azure_sec.azurerm_storage_account.bad",
				"mode":    "managed",
				"type":    "azurerm_storage_account",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"https_traffic_only_enabled": false,
						"min_tls_version":            "TLS1_0",
					},
				},
			},
			{
				"address": "module.azure_sec.azurerm_mssql_server.bad",
				"mode":    "managed",
				"type":    "azurerm_mssql_server",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"minimum_tls_version": "1.0"},
				},
			},
			{
				"address": "module.azure_sec.azurerm_postgresql_flexible_server.bad",
				"mode":    "managed",
				"type":    "azurerm_postgresql_flexible_server",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"public_network_access_enabled": true,
						"backup_retention_days":         3,
					},
				},
			},
			{
				"address": "module.azure_sec.azurerm_key_vault.bad",
				"mode":    "managed",
				"type":    "azurerm_key_vault",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"soft_delete_retention_days": 7,
						"purge_protection_enabled":   false,
						"enable_rbac_authorization":  false,
					},
				},
			},
			{
				"address": "google_sql_database_instance.advisory_sql",
				"mode":    "managed",
				"type":    "google_sql_database_instance",
				"name":    "advisory_sql",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"settings": []any{map[string]any{
							"ip_configuration":     []any{map[string]any{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}},
							"backup_configuration": []any{map[string]any{"enabled": false}},
						}},
					},
				},
			},
			{
				"address": "module.gcp_app.module.shared_gcp.google_storage_bucket.bad",
				"mode":    "managed",
				"type":    "google_storage_bucket",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"uniform_bucket_level_access": false,
						"public_access_prevention":    "inherited",
					},
				},
			},
			{
				"address": "module.gcp_app.module.shared_gcp.google_compute_instance.bad",
				"mode":    "managed",
				"type":    "google_compute_instance",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"can_ip_forward":           true,
						"shielded_instance_config": []any{map[string]any{"enable_secure_boot": false}},
					},
				},
			},
			{
				"address": "module.gcp_app.module.shared_gcp.google_kms_crypto_key.bad",
				"mode":    "managed",
				"type":    "google_kms_crypto_key",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"rotation_period": ""},
				},
			},
			{
				"address": "module.gcp_app.module.shared_gcp.google_compute_firewall.bad",
				"mode":    "managed",
				"type":    "google_compute_firewall",
				"name":    "bad",
				"change": map[string]any{
					"actions": []string{"create"},
					"after": map[string]any{
						"log_config": []any{map[string]any{"metadata": "EXCLUDE_ALL_METADATA"}},
					},
				},
			},
		},
	}

	planPath := filepath.Join(tmpDir, "plan.json")
	planBytes, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatalf("marshal plan.json: %v", err)
	}
	if err := os.WriteFile(planPath, planBytes, 0o600); err != nil {
		t.Fatalf("write plan.json: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Execute(ctx, []string{
		"remediate",
		"--pack", "all",
		"--plan", planPath,
		"--tf-dir", tmpDir,
		"--include-skipped",
		"--write",
		"--format", "json",
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("expected ExitOK (%d), got %d; stderr: %s", ExitOK, code, stderr.String())
	}

	var rep model.RemediationReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal RemediationReport: %v\nOutput:\n%s", err, stdout.String())
	}

	if rep.Summary.TotalViolations != rep.Summary.PatchedCount+rep.Summary.SkippedCount {
		t.Errorf("summary invariant failed: %+v", rep.Summary)
	}

	// Verify all 26 auto-patchable starter rules produced patches and valid HCL.
	patchedRules := map[string]bool{}
	for i, p := range rep.Patches {
		if p.RuleID != "" {
			patchedRules[p.RuleID] = true
		}
		if _, diags := hclwrite.ParseConfig([]byte(p.PatchedHCL), p.FilePath, hcl.Pos{Line: 1, Column: 1}); diags.HasErrors() {
			t.Errorf("patch[%d] (%s) invalid HCL: %s", i, p.ResourceAddress, diags.Error())
		}
	}

	// Verify 26 auto-patchable rules (12 AWS + 8 Azure + 6 GCP) were patched.
	advisoryRules := map[string]bool{"gcp-sql-ssl": true, "gcp-sql-backup": true}
	var expected26 []string
	expected26 = append(expected26, allAWSRuleIDs...)
	expected26 = append(expected26, allAzureRuleIDs...)
	for _, r := range allGCPRuleIDs {
		if !advisoryRules[r] {
			expected26 = append(expected26, r)
		}
	}
	for _, r := range expected26 {
		if !patchedRules[r] {
			t.Errorf("expected auto-patchable starter rule %q to produce a patch", r)
		}
	}

	// Verify skipped diagnostics cover the 2 advisory Cloud SQL rules, external module, and var.* expression.
	skippedByRuleAndAddr := map[string]model.RemediationDiagnostic{}
	for _, d := range rep.Skipped {
		skippedByRuleAndAddr[d.RuleID+"|"+d.ResourceAddress] = d
	}
	if d, ok := skippedByRuleAndAddr["gcp-sql-ssl|google_sql_database_instance.advisory_sql"]; !ok || d.Reason != model.SkipReasonMissingRemediationMetadata {
		t.Errorf("expected missing_remediation_metadata for gcp-sql-ssl, got %+v", d)
	}
	if d, ok := skippedByRuleAndAddr["gcp-sql-backup|google_sql_database_instance.advisory_sql"]; !ok || d.Reason != model.SkipReasonMissingRemediationMetadata {
		t.Errorf("expected missing_remediation_metadata for gcp-sql-backup, got %+v", d)
	}
	if d, ok := skippedByRuleAndAddr["aws-ebs-encrypt|module.ext_s3.aws_ebs_volume.ext_vol"]; !ok || d.Reason != model.SkipReasonExternalModuleSource {
		t.Errorf("expected external_module_source for module.ext_s3, got %+v", d)
	}
	if d, ok := skippedByRuleAndAddr["aws-ebs-encrypt|aws_ebs_volume.var_driven"]; !ok || d.Reason != model.SkipReasonUnsupportedExpression {
		t.Errorf("expected unsupported_expression for var_driven, got %+v", d)
	}

	// Verify --write preserved var.enable_ebs on disk and patched local/sibling modules cleanly.
	diskRoot, err := os.ReadFile(rootTFPath)
	if err != nil {
		t.Fatalf("read root main.tf: %v", err)
	}
	if !strings.Contains(string(diskRoot), "encrypted         = var.enable_ebs") && !strings.Contains(string(diskRoot), "encrypted = var.enable_ebs") {
		t.Errorf("var_driven expression was unexpectedly overwritten on disk:\n%s", string(diskRoot))
	}
	diskAzure, err := os.ReadFile(azureTFPath)
	if err != nil {
		t.Fatalf("read azure main.tf: %v", err)
	}
	if !containsNormalizedHCLAssignment(string(diskAzure), "https_traffic_only_enabled = true") {
		t.Errorf("azure local module was not patched on disk:\n%s", string(diskAzure))
	}
	diskGCP, err := os.ReadFile(sharedGCPTFPath)
	if err != nil {
		t.Fatalf("read shared_gcp main.tf: %v", err)
	}
	if !containsNormalizedHCLAssignment(string(diskGCP), "uniform_bucket_level_access = true") {
		t.Errorf("gcp sibling module was not patched on disk:\n%s", string(diskGCP))
	}
}

func TestCLI_Remediate_JSONBackwardsCompatVsIncludeSkipped(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	mainTF := `variable "enable_ebs" {
  type    = bool
  default = false
}

resource "aws_ebs_volume" "patchable" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_ebs_volume" "var_driven" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.enable_ebs
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(mainTF), 0o600); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}

	plan := map[string]any{
		"format_version":    "1.2",
		"terraform_version": "1.9.0",
		"resource_changes": []map[string]any{
			{
				"address": "aws_ebs_volume.patchable",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "patchable",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
			{
				"address": "aws_ebs_volume.var_driven",
				"mode":    "managed",
				"type":    "aws_ebs_volume",
				"name":    "var_driven",
				"change": map[string]any{
					"actions": []string{"create"},
					"after":   map[string]any{"encrypted": false},
				},
			},
		},
	}
	planPath := filepath.Join(tmpDir, "plan.json")
	planBytes, _ := json.Marshal(plan)
	if err := os.WriteFile(planPath, planBytes, 0o600); err != nil {
		t.Fatalf("write plan.json: %v", err)
	}

	t.Run("DefaultJSON_RemainsArray", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"remediate", "--pack", "aws", "--plan", planPath, "--tf-dir", tmpDir, "--format", "json",
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK, got %d; stderr: %s", code, stderr.String())
		}
		var patches []model.RemediationPatch
		if err := json.Unmarshal(stdout.Bytes(), &patches); err != nil {
			t.Fatalf("default --format json must unmarshal as []RemediationPatch: %v\n%s", err, stdout.String())
		}
		if len(patches) != 1 || patches[0].ResourceAddress != "aws_ebs_volume.patchable" {
			t.Errorf("unexpected patches: %+v", patches)
		}
	})

	t.Run("IncludeSkippedJSON_ReturnsFullReport", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"remediate", "--pack", "aws", "--plan", planPath, "--tf-dir", tmpDir, "--include-skipped", "--format", "json",
		}, &stdout, &stderr)
		if code != ExitOK {
			t.Fatalf("expected ExitOK, got %d; stderr: %s", code, stderr.String())
		}
		var rep model.RemediationReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("--include-skipped --format json must unmarshal as RemediationReport: %v\n%s", err, stdout.String())
		}
		if rep.Summary.TotalViolations != 2 || rep.Summary.PatchedCount != 1 || rep.Summary.SkippedCount != 1 {
			t.Errorf("unexpected summary: %+v", rep.Summary)
		}
		if rep.Summary.ByReason[string(model.SkipReasonUnsupportedExpression)] != 1 {
			t.Errorf("expected by_reason[unsupported_expression]=1, got %+v", rep.Summary.ByReason)
		}
	})

	t.Run("TableMarkdownSARIF_SurfaceSkippedWithoutFlag", func(t *testing.T) {
		for _, tc := range []struct {
			format string
			want   string
		}{
			{format: "table", want: "Skipped / Manual-Review Violations: 1"},
			{format: "markdown", want: "## Skipped / Manual-Review Violations (1)"},
			{format: "sarif", want: "TFSIM-REMEDIATE-SKIPPED"},
		} {
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{
				"remediate", "--pack", "aws", "--plan", planPath, "--tf-dir", tmpDir, "--format", tc.format,
			}, &stdout, &stderr)
			if code != ExitOK {
				t.Fatalf("format %s expected ExitOK, got %d; stderr: %s", tc.format, code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("format %s missing %q:\n%s", tc.format, tc.want, stdout.String())
			}
		}
	})

	t.Run("InvalidFormat_Exits2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := Execute(ctx, []string{
			"remediate", "--pack", "aws", "--plan", planPath, "--tf-dir", tmpDir, "--include-skipped", "--format", "yaml",
		}, &stdout, &stderr)
		if code != ExitError {
			t.Fatalf("expected ExitError (2), got %d", code)
		}
	})
}
