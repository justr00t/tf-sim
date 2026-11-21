package tfsim.aws.rds

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 7: Require storage encryption on AWS RDS DB instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	not is_delete(rc)
	not has_rds_storage_encrypted(rc)
	violation := {
		"rule_id": "aws-rds-encrypt",
		"severity": "CRITICAL",
		"message": sprintf("RDS instance %s must have storage_encrypted = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["storage_encrypted"],
			"suggested_value": true,
			"description": "Set storage_encrypted = true on the aws_db_instance resource",
		},
	}
}

has_rds_storage_encrypted(rc) if {
	rc.change.after.storage_encrypted == true
}

# Rule 8: Disallow publicly accessible AWS RDS DB instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	not is_delete(rc)
	not is_rds_private(rc)
	violation := {
		"rule_id": "aws-rds-public",
		"severity": "CRITICAL",
		"message": sprintf("RDS instance %s must set publicly_accessible = false", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["publicly_accessible"],
			"suggested_value": false,
			"description": "Set publicly_accessible = false on the aws_db_instance resource",
		},
	}
}

is_rds_private(rc) if {
	rc.change.after.publicly_accessible == false
}

# Rule 9: Require IAM database authentication on AWS RDS DB instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	not is_delete(rc)
	not has_rds_iam_auth(rc)
	violation := {
		"rule_id": "aws-rds-iam-auth",
		"severity": "MEDIUM",
		"message": sprintf("RDS instance %s must have iam_database_authentication_enabled = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["iam_database_authentication_enabled"],
			"suggested_value": true,
			"description": "Set iam_database_authentication_enabled = true on the aws_db_instance resource",
		},
	}
}

has_rds_iam_auth(rc) if {
	rc.change.after.iam_database_authentication_enabled == true
}
