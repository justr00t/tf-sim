package tfsim.azure.keyvault

import rego.v1

# Helper function to detect delete-only operations
is_delete(rc) if {
	rc.change.actions == ["delete"]
}

is_delete(rc) if {
	rc.actions == ["delete"]
}

# Rule 18: Require >= 90 days soft-delete retention on Azure Key Vaults
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_key_vault"
	not is_delete(rc)
	not has_kv_soft_delete_retention(rc)
	violation := {
		"rule_id": "azure-kv-softdel",
		"severity": "MEDIUM",
		"message": sprintf("Azure Key Vault %s must set soft_delete_retention_days >= 90", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["soft_delete_retention_days"],
			"suggested_value": 90,
			"description": "Set soft_delete_retention_days = 90 on the azurerm_key_vault resource",
		},
	}
}

has_kv_soft_delete_retention(rc) if {
	is_number(rc.change.after.soft_delete_retention_days)
	rc.change.after.soft_delete_retention_days >= 90
}

# Rule 19: Require purge protection enabled on Azure Key Vaults
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_key_vault"
	not is_delete(rc)
	not has_kv_purge_protection(rc)
	violation := {
		"rule_id": "azure-kv-purge",
		"severity": "HIGH",
		"message": sprintf("Azure Key Vault %s must set purge_protection_enabled = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["purge_protection_enabled"],
			"suggested_value": true,
			"description": "Set purge_protection_enabled = true on the azurerm_key_vault resource",
		},
	}
}

has_kv_purge_protection(rc) if {
	rc.change.after.purge_protection_enabled == true
}

# Rule 20: Require RBAC authorization on Azure Key Vaults
deny contains violation if {
	some rc in input.resource_changes
	rc.type == "azurerm_key_vault"
	not is_delete(rc)
	not has_kv_rbac_auth(rc)
	violation := {
		"rule_id": "azure-kv-rbac",
		"severity": "MEDIUM",
		"message": sprintf("Azure Key Vault %s must set enable_rbac_authorization = true", [rc.address]),
		"resource_address": rc.address,
		"resource_type": rc.type,
		"resource_name": rc.name,
		"remediation": {
			"attribute_path": ["enable_rbac_authorization"],
			"suggested_value": true,
			"description": "Set enable_rbac_authorization = true on the azurerm_key_vault resource",
		},
	}
}

has_kv_rbac_auth(rc) if {
	rc.change.after.enable_rbac_authorization == true
}
