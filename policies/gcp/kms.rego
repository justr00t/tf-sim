package tfsim.gcp.kms

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 27: Require automatic key rotation within 90 days (7776000s) on Cloud KMS crypto keys
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_kms_crypto_key"
	not is_delete(rc)
	not has_valid_kms_rotation(rc)
	violation := {
		"rule_id": "gcp-kms-rotation",
		"severity": "MEDIUM",
		"message": sprintf("Cloud KMS crypto key %s must configure rotation_period <= 7776000s (90 days)", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["rotation_period"],
			"suggested_value": "7776000s",
			"description": "Set rotation_period = \"7776000s\" (90 days) on the google_kms_crypto_key resource",
		},
	}
}

has_valid_kms_rotation(rc) if {
	period := rc.change.after.rotation_period
	is_string(period)
	endswith(period, "s")
	seconds := to_number(trim_suffix(period, "s"))
	is_number(seconds)
	seconds > 0
	seconds <= 7776000
}
