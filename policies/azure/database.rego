package tfsim.azure.database

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 15: Require minimum TLS 1.2 on Azure SQL Servers
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_mssql_server"
	not is_delete(rc)
	not has_mssql_min_tls(rc)
	violation := {
		"rule_id": "azure-mssql-tls",
		"severity": "HIGH",
		"message": sprintf("Azure SQL Server %s must set minimum_tls_version = \"1.2\" or higher", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["minimum_tls_version"],
			"suggested_value": "1.2",
			"description": "Set minimum_tls_version = \"1.2\" on the azurerm_mssql_server resource",
		},
	}
}

has_mssql_min_tls(rc) if {
	rc.change.after.minimum_tls_version in ["1.2", "1.3"]
}

# Rule 16: Disallow public network access on Azure PostgreSQL Flexible Servers
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_postgresql_flexible_server"
	not is_delete(rc)
	not is_psql_flex_private(rc)
	violation := {
		"rule_id": "azure-psql-flex-public",
		"severity": "CRITICAL",
		"message": sprintf("Azure PostgreSQL Flexible Server %s must set public_network_access_enabled = false", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["public_network_access_enabled"],
			"suggested_value": false,
			"description": "Set public_network_access_enabled = false on the azurerm_postgresql_flexible_server resource",
		},
	}
}

is_psql_flex_private(rc) if {
	rc.change.after.public_network_access_enabled == false
}

# Rule 17: Require >= 7 days backup retention on Azure PostgreSQL Flexible Servers
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_postgresql_flexible_server"
	not is_delete(rc)
	not has_psql_flex_backup_retention(rc)
	violation := {
		"rule_id": "azure-psql-flex-backup",
		"severity": "MEDIUM",
		"message": sprintf("Azure PostgreSQL Flexible Server %s must set backup_retention_days >= 7", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["backup_retention_days"],
			"suggested_value": 7,
			"description": "Set backup_retention_days = 7 on the azurerm_postgresql_flexible_server resource",
		},
	}
}

has_psql_flex_backup_retention(rc) if {
	is_number(rc.change.after.backup_retention_days)
	rc.change.after.backup_retention_days >= 7
}
