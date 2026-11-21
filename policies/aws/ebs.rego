package tfsim.aws.ebs

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 10: Require encryption on AWS EBS volumes
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_ebs_volume"
	not is_delete(rc)
	not has_ebs_encrypted(rc)
	violation := {
		"rule_id": "aws-ebs-encrypt",
		"severity": "HIGH",
		"message": sprintf("EBS volume %s must have encrypted = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["encrypted"],
			"suggested_value": true,
			"description": "Set encrypted = true on the aws_ebs_volume resource",
		},
	}
}

has_ebs_encrypted(rc) if {
	rc.change.after.encrypted == true
}
