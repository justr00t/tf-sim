package tfsim

import rego.v1

is_delete(rc) if {
	"delete" in rc.change.actions
}

# Silent Fail-Open Bug 1: Typo in attribute name (https_only_enabled instead of https_traffic_only_enabled)
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not is_delete(rc)
	rc.change.after.https_only_enabled == false
	violation := {
		"rule_id": "AZURE-STORAGE-BROKEN-001",
		"severity": "HIGH",
		"message": sprintf("Storage account %s fail open typo", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

# Silent Fail-Open Bug 2: Typo in nested block attribute (invalid_encrypt instead of sse_algorithm)
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not is_delete(rc)
	rc.change.after.server_side_encryption_configuration[_].rule[_].invalid_encrypt == true
	violation := {
		"rule_id": "AWS-S3-BROKEN-001",
		"severity": "HIGH",
		"message": sprintf("S3 bucket %s nested fail open typo", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}
