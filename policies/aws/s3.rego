package tfsim.aws.s3

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 1: Require block_public_acls = true on S3 Public Access Block
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	not is_delete(rc)
	not has_block_public_acls(rc)
	violation := {
		"rule_id": "aws-s3-pab-acls",
		"severity": "HIGH",
		"message": sprintf("S3 public access block %s must set block_public_acls = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["block_public_acls"],
			"suggested_value": true,
			"description": "Set block_public_acls = true to block public ACLs on the S3 bucket",
		},
	}
}

has_block_public_acls(rc) if {
	rc.change.after.block_public_acls == true
}

# Rule 2: Require block_public_policy = true on S3 Public Access Block
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	not is_delete(rc)
	not has_block_public_policy(rc)
	violation := {
		"rule_id": "aws-s3-pab-policy",
		"severity": "HIGH",
		"message": sprintf("S3 public access block %s must set block_public_policy = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["block_public_policy"],
			"suggested_value": true,
			"description": "Set block_public_policy = true to block public bucket policies",
		},
	}
}

has_block_public_policy(rc) if {
	rc.change.after.block_public_policy == true
}

# Rule 3: Require ignore_public_acls = true on S3 Public Access Block
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	not is_delete(rc)
	not has_ignore_public_acls(rc)
	violation := {
		"rule_id": "aws-s3-pab-ignore",
		"severity": "HIGH",
		"message": sprintf("S3 public access block %s must set ignore_public_acls = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["ignore_public_acls"],
			"suggested_value": true,
			"description": "Set ignore_public_acls = true to ignore existing public ACLs on the S3 bucket",
		},
	}
}

has_ignore_public_acls(rc) if {
	rc.change.after.ignore_public_acls == true
}

# Rule 4: Require restrict_public_buckets = true on S3 Public Access Block
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	not is_delete(rc)
	not has_restrict_public_buckets(rc)
	violation := {
		"rule_id": "aws-s3-pab-restrict",
		"severity": "HIGH",
		"message": sprintf("S3 public access block %s must set restrict_public_buckets = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["restrict_public_buckets"],
			"suggested_value": true,
			"description": "Set restrict_public_buckets = true to restrict cross-account public access",
		},
	}
}

has_restrict_public_buckets(rc) if {
	rc.change.after.restrict_public_buckets == true
}

# Rule 5: Require KMS server-side encryption on S3 Bucket Encryption Configuration
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	not is_delete(rc)
	not has_s3_sse_kms(rc)
	violation := {
		"rule_id": "aws-s3-sse-kms",
		"severity": "HIGH",
		"message": sprintf("S3 server-side encryption configuration %s must use KMS encryption (aws:kms)", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["rule", "apply_server_side_encryption_by_default", "sse_algorithm"],
			"suggested_value": "aws:kms",
			"description": "Configure rule.apply_server_side_encryption_by_default.sse_algorithm = \"aws:kms\"",
		},
	}
}

has_s3_sse_kms(rc) if {
	some r in rc.change.after.rule
	some def in r.apply_server_side_encryption_by_default
	def.sse_algorithm in ["aws:kms", "aws:kms:dsse"]
}

# Rule 6: Require versioning enabled on S3 Bucket Versioning
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_versioning"
	not is_delete(rc)
	not has_s3_versioning_enabled(rc)
	violation := {
		"rule_id": "aws-s3-versioning",
		"severity": "MEDIUM",
		"message": sprintf("S3 bucket versioning %s must set versioning_configuration.status = \"Enabled\"", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["versioning_configuration", "status"],
			"suggested_value": "Enabled",
			"description": "Set versioning_configuration.status = \"Enabled\"",
		},
	}
}

has_s3_versioning_enabled(rc) if {
	some cfg in rc.change.after.versioning_configuration
	cfg.status == "Enabled"
}
