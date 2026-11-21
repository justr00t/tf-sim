package tfsim.gcp.sql

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 23: Require SSL/TLS enforcement on Cloud SQL database instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_sql_database_instance"
	not is_delete(rc)
	not has_sql_ssl_enforced(rc)
	violation := {
		"rule_id": "gcp-sql-ssl",
		"severity": "HIGH",
		"message": sprintf("Cloud SQL instance %s must enforce SSL via settings.ip_configuration.ssl_mode", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

has_sql_ssl_enforced(rc) if {
	some s in rc.change.after.settings
	some ip in s.ip_configuration
	ip.ssl_mode in ["ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"]
}

# Rule 24: Require automated backups enabled on Cloud SQL database instances
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "google_sql_database_instance"
	not is_delete(rc)
	not has_sql_backup_enabled(rc)
	violation := {
		"rule_id": "gcp-sql-backup",
		"severity": "MEDIUM",
		"message": sprintf("Cloud SQL instance %s must enable automated backups via settings.backup_configuration.enabled = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
	}
}

has_sql_backup_enabled(rc) if {
	some s in rc.change.after.settings
	some b in s.backup_configuration
	b.enabled == true
}
