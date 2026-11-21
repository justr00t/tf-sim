package tfsim.gcp.storage

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 21: Require uniform bucket-level access on Google Cloud Storage buckets
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	not is_delete(rc)
	not has_storage_ubla(rc)
	violation := {
		"rule_id": "gcp-storage-ubla",
		"severity": "HIGH",
		"message": sprintf("Cloud Storage bucket %s must set uniform_bucket_level_access = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["uniform_bucket_level_access"],
			"suggested_value": true,
			"description": "Set uniform_bucket_level_access = true on the google_storage_bucket resource",
		},
	}
}

has_storage_ubla(rc) if {
	rc.change.after.uniform_bucket_level_access == true
}

# Rule 22: Require enforced public access prevention on Google Cloud Storage buckets
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	not is_delete(rc)
	not has_storage_public_access_prevention(rc)
	violation := {
		"rule_id": "gcp-storage-public",
		"severity": "HIGH",
		"message": sprintf("Cloud Storage bucket %s must set public_access_prevention = \"enforced\"", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["public_access_prevention"],
			"suggested_value": "enforced",
			"description": "Set public_access_prevention = \"enforced\" on the google_storage_bucket resource",
		},
	}
}

has_storage_public_access_prevention(rc) if {
	rc.change.after.public_access_prevention == "enforced"
}
