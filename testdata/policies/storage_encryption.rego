package tfsim

import rego.v1

# Helper function to detect delete operations
is_delete(rc) if {
	"delete" in rc.change.actions
}

is_delete(rc) if {
	"delete" in rc.actions
}

# AWS S3: Require server-side encryption configuration with KMS or AES256
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not is_delete(rc)
	not has_s3_encryption(rc)
	violation := {
		"rule_id": "AWS-S3-ENCRYPT-001",
		"severity": "HIGH",
		"message": sprintf("S3 bucket %s must have server-side encryption enabled", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"],
			"suggested_value": "aws:kms",
			"description": "Enable server-side encryption with KMS",
		},
	}
}

has_s3_encryption(rc) if {
	some ssec in rc.change.after.server_side_encryption_configuration
	some rule in ssec.rule
	some def in rule.apply_server_side_encryption_by_default
	def.sse_algorithm != ""
}

# Azure Storage Account: Require HTTPS traffic only enabled
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not is_delete(rc)
	rc.change.after.https_traffic_only_enabled == false
	violation := {
		"rule_id": "AZURE-STORAGE-HTTPS-001",
		"severity": "HIGH",
		"message": sprintf("Storage account %s must enforce HTTPS traffic only", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["https_traffic_only_enabled"],
			"suggested_value": true,
			"description": "Set https_traffic_only_enabled = true",
		},
	}
}

# GCP Storage Bucket: Require uniform bucket-level access enabled
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	not is_delete(rc)
	rc.change.after.uniform_bucket_level_access == false
	violation := {
		"rule_id": "GCP-STORAGE-UBLA-001",
		"severity": "MEDIUM",
		"message": sprintf("Cloud Storage bucket %s must have uniform bucket-level access enabled", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["uniform_bucket_level_access"],
			"suggested_value": true,
			"description": "Set uniform_bucket_level_access = true",
		},
	}
}
