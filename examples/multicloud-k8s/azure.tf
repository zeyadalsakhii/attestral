# Intentionally insecure Azure fixtures for Attestral rule coverage.

resource "azurerm_storage_account" "public" {
  name                            = "acmepublicdata"
  enable_https_traffic_only       = false
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"
  }
}

resource "azurerm_mssql_server" "db" {
  name                          = "acme-sql"
  public_network_access_enabled = true
}

resource "azurerm_network_security_rule" "open_ssh" {
  name                       = "allow-all-ssh"
  access                     = "Allow"
  direction                  = "Inbound"
  protocol                   = "Tcp"
  destination_port_range     = "22"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
}

resource "azurerm_key_vault" "vault" {
  name                     = "acme-kv"
  purge_protection_enabled = false
}
