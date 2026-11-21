package tfsim.aws.kms

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 12: Require automatic key rotation on AWS KMS keys
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_kms_key"
	not is_delete(rc)
	not has_kms_key_rotation(rc)
	violation := {
		"rule_id": "aws-kms-rotation",
		"severity": "MEDIUM",
		"message": sprintf("KMS key %s must have enable_key_rotation = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["enable_key_rotation"],
			"suggested_value": true,
			"description": "Set enable_key_rotation = true on the aws_kms_key resource",
		},
	}
}

has_kms_key_rotation(rc) if {
	rc.change.after.enable_key_rotation == true
}
