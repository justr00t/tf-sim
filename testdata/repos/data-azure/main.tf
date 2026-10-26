# Data Platform - Azure Storage Infrastructure
# Managed by Data Engineering

resource "azurerm_storage_account" "compliant_lake" {
  name                       = "datalakeprod"
  resource_group_name        = "rg-data"
  location                   = "eastus2"
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
}

# Legacy data ingestion storage account (non-compliant HTTPS setting)
resource "azurerm_storage_account" "insecure_transfer" {
  name                     = "insecuretransfer"
  resource_group_name      = "rg-data"
  location                 = "eastus2"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Legacy toggle - must be remediated to true
  https_traffic_only_enabled = false
}
