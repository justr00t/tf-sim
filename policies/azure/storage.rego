package tfsim.azure.storage

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 13: Require HTTPS-only traffic on Azure Storage Accounts
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not is_delete(rc)
	not has_storage_https_only(rc)
	violation := {
		"rule_id": "azure-storage-https",
		"severity": "HIGH",
		"message": sprintf("Azure Storage Account %s must set https_traffic_only_enabled = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["https_traffic_only_enabled"],
			"suggested_value": true,
			"description": "Set https_traffic_only_enabled = true on the azurerm_storage_account resource",
		},
	}
}

has_storage_https_only(rc) if {
	rc.change.after.https_traffic_only_enabled == true
}

# Rule 14: Require minimum TLS 1.2 on Azure Storage Accounts
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	not is_delete(rc)
	not has_storage_min_tls(rc)
	violation := {
		"rule_id": "azure-storage-tls",
		"severity": "HIGH",
		"message": sprintf("Azure Storage Account %s must set min_tls_version = \"TLS1_2\"", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["min_tls_version"],
			"suggested_value": "TLS1_2",
			"description": "Set min_tls_version = \"TLS1_2\" on the azurerm_storage_account resource",
		},
	}
}

has_storage_min_tls(rc) if {
	rc.change.after.min_tls_version == "TLS1_2"
}
