# Starter Policy Pack - Azure Non-Compliant Infrastructure Fixture
# Covers all 8 Azure starter policy rules (explicit non-compliant + missing attributes)

resource "azurerm_storage_account" "explicit_bad" {
  name                       = "badstorage01"
  https_traffic_only_enabled = false
  min_tls_version            = "TLS1_0"
}

resource "azurerm_storage_account" "missing_attrs" {
  name = "missingstorage01"
}

resource "azurerm_mssql_server" "explicit_bad" {
  name                = "bad-mssql-srv"
  minimum_tls_version = "1.0"
}

resource "azurerm_mssql_server" "missing_attrs" {
  name = "missing-mssql-srv"
}

resource "azurerm_postgresql_flexible_server" "explicit_bad" {
  name                          = "bad-psql-flex"
  public_network_access_enabled = true
  backup_retention_days         = 3
}

resource "azurerm_postgresql_flexible_server" "missing_attrs" {
  name = "missing-psql-flex"
}

resource "azurerm_key_vault" "explicit_bad" {
  name                       = "bad-kv-01"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = false
}

resource "azurerm_key_vault" "missing_attrs" {
  name = "missing-kv-01"
}
