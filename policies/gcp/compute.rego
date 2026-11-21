package tfsim.gcp.compute

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 25: Require Shielded VM Secure Boot on Google Compute Engine instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_compute_instance"
	not is_delete(rc)
	not has_compute_secure_boot(rc)
	violation := {
		"rule_id": "gcp-compute-shielded",
		"severity": "MEDIUM",
		"message": sprintf("Compute Engine instance %s must enable shielded_instance_config.enable_secure_boot = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["shielded_instance_config", "enable_secure_boot"],
			"suggested_value": true,
			"description": "Set shielded_instance_config.enable_secure_boot = true on the google_compute_instance resource",
		},
	}
}

has_compute_secure_boot(rc) if {
	some cfg in rc.change.after.shielded_instance_config
	cfg.enable_secure_boot == true
}

# Rule 26: Disallow IP forwarding on Google Compute Engine instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_compute_instance"
	not is_delete(rc)
	not is_compute_ip_forward_disabled(rc)
	violation := {
		"rule_id": "gcp-compute-ip-fwd",
		"severity": "HIGH",
		"message": sprintf("Compute Engine instance %s must set can_ip_forward = false", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["can_ip_forward"],
			"suggested_value": false,
			"description": "Set can_ip_forward = false on the google_compute_instance resource",
		},
	}
}

is_compute_ip_forward_disabled(rc) if {
	rc.change.after.can_ip_forward == false
}
