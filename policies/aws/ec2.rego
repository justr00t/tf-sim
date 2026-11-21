package tfsim.aws.ec2

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 11: Require EBS optimization on AWS EC2 instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	not is_delete(rc)
	not has_ec2_ebs_optimized(rc)
	violation := {
		"rule_id": "aws-ec2-ebs-opt",
		"severity": "LOW",
		"message": sprintf("EC2 instance %s must have ebs_optimized = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["ebs_optimized"],
			"suggested_value": true,
			"description": "Set ebs_optimized = true on the aws_instance resource",
		},
	}
}

has_ec2_ebs_optimized(rc) if {
	rc.change.after.ebs_optimized == true
}
