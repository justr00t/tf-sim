package tfsim.gcp.firewall

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 28: Require firewall logging with full metadata on Google Compute Firewalls
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_compute_firewall"
	not is_delete(rc)
	not has_firewall_logging(rc)
	violation := {
		"rule_id": "gcp-firewall-log",
		"severity": "MEDIUM",
		"message": sprintf("Compute Firewall %s must enable log_config.metadata = \"INCLUDE_ALL_METADATA\"", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["log_config", "metadata"],
			"suggested_value": "INCLUDE_ALL_METADATA",
			"description": "Set log_config.metadata = \"INCLUDE_ALL_METADATA\" on the google_compute_firewall resource",
		},
	}
}

has_firewall_logging(rc) if {
	some cfg in rc.change.after.log_config
	cfg.metadata == "INCLUDE_ALL_METADATA"
}
