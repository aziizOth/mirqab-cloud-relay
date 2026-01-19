# Cloud Relay - Azure Infrastructure
# Deploys AKS cluster with all required services
# Supports UAE North (Dubai) and Saudi Arabia regions for NCA compliance

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.45"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }

  # Uncomment for remote state
  # backend "azurerm" {
  #   resource_group_name  = "offensight-tfstate"
  #   storage_account_name = "offensighttfstate"
  #   container_name       = "tfstate"
  #   key                  = "cloud-relay.tfstate"
  # }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

provider "azuread" {}

# Data sources
data "azurerm_client_config" "current" {}

data "azuread_client_config" "current" {}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${var.cluster_name}-rg"
  location = var.location

  tags = {
    Project     = "OffenSight"
    Component   = "CloudRelay"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "${var.cluster_name}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_cidr]

  tags = azurerm_resource_group.main.tags
}

# Subnets
resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.aks_subnet_cidr]
}

resource "azurerm_subnet" "database" {
  name                 = "database-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.database_subnet_cidr]

  delegation {
    name = "postgresql-delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "redis" {
  name                 = "redis-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.redis_subnet_cidr]
}

# Private DNS Zone for PostgreSQL
resource "azurerm_private_dns_zone" "postgresql" {
  name                = "${var.cluster_name}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgresql" {
  name                  = "postgresql-vnet-link"
  private_dns_zone_name = azurerm_private_dns_zone.postgresql.name
  virtual_network_id    = azurerm_virtual_network.main.id
  resource_group_name   = azurerm_resource_group.main.name
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name                = "default"
    node_count          = var.node_count
    vm_size             = var.node_vm_size
    vnet_subnet_id      = azurerm_subnet.aks.id
    enable_auto_scaling = true
    min_count           = var.node_min_count
    max_count           = var.node_max_count

    # Use spot instances for non-production
    dynamic "upgrade_settings" {
      for_each = var.environment != "production" ? [1] : []
      content {
        max_surge = "33%"
      }
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    load_balancer_sku = "standard"
    service_cidr      = "10.0.0.0/16"
    dns_service_ip    = "10.0.0.10"
  }

  # Enable Azure Policy for Kubernetes
  azure_policy_enabled = true

  # Enable Container Insights
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  tags = azurerm_resource_group.main.tags
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.cluster_name}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = azurerm_resource_group.main.tags
}

# PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${var.cluster_name}-db"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "15"
  delegated_subnet_id    = azurerm_subnet.database.id
  private_dns_zone_id    = azurerm_private_dns_zone.postgresql.id
  administrator_login    = "cloudrelay"
  administrator_password = random_password.db_password.result
  zone                   = "1"

  storage_mb = 32768
  sku_name   = var.db_sku

  backup_retention_days        = 7
  geo_redundant_backup_enabled = var.environment == "production"

  tags = azurerm_resource_group.main.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgresql]
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "cloudrelay"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Azure Cache for Redis
resource "azurerm_redis_cache" "main" {
  name                = "${var.cluster_name}-redis"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    maxmemory_policy = "volatile-lru"
  }

  tags = azurerm_resource_group.main.tags
}

# Storage Account for payloads
resource "azurerm_storage_account" "payloads" {
  name                     = replace("${var.cluster_name}payloads", "-", "")
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = var.environment == "production" ? "GRS" : "LRS"

  blob_properties {
    versioning_enabled = true
  }

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_storage_container" "payloads" {
  name                  = "payloads"
  storage_account_name  = azurerm_storage_account.payloads.name
  container_access_type = "private"
}

# Key Vault for secrets
resource "azurerm_key_vault" "main" {
  name                        = "${var.cluster_name}-kv"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge"
    ]
  }

  # AKS access
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id

    secret_permissions = [
      "Get", "List"
    ]
  }

  tags = azurerm_resource_group.main.tags
}

# Store secrets in Key Vault
resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db_password.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "redis_key" {
  name         = "redis-key"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id
}

# Configure kubernetes provider
provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
  }
}

# Install nginx ingress controller
resource "helm_release" "ingress_nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  create_namespace = true
  version          = "4.8.0"

  set {
    name  = "controller.service.type"
    value = "LoadBalancer"
  }

  set {
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/azure-load-balancer-health-probe-request-path"
    value = "/healthz"
  }

  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install cert-manager
resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  namespace        = "cert-manager"
  create_namespace = true
  version          = "v1.13.0"

  set {
    name  = "installCRDs"
    value = "true"
  }

  depends_on = [azurerm_kubernetes_cluster.main]
}

# Create cloud-relay namespace
resource "kubernetes_namespace" "cloud_relay" {
  metadata {
    name = "cloud-relay"

    labels = {
      name        = "cloud-relay"
      environment = var.environment
    }
  }

  depends_on = [azurerm_kubernetes_cluster.main]
}

# Create secrets for database and redis
resource "kubernetes_secret" "db_credentials" {
  metadata {
    name      = "db-credentials"
    namespace = kubernetes_namespace.cloud_relay.metadata[0].name
  }

  data = {
    host     = azurerm_postgresql_flexible_server.main.fqdn
    port     = "5432"
    database = "cloudrelay"
    username = "cloudrelay"
    password = random_password.db_password.result
  }

  depends_on = [kubernetes_namespace.cloud_relay]
}

resource "kubernetes_secret" "redis_credentials" {
  metadata {
    name      = "redis-credentials"
    namespace = kubernetes_namespace.cloud_relay.metadata[0].name
  }

  data = {
    host     = azurerm_redis_cache.main.hostname
    port     = "6380"
    password = azurerm_redis_cache.main.primary_access_key
    ssl      = "true"
  }

  depends_on = [kubernetes_namespace.cloud_relay]
}

resource "kubernetes_secret" "storage_credentials" {
  metadata {
    name      = "storage-credentials"
    namespace = kubernetes_namespace.cloud_relay.metadata[0].name
  }

  data = {
    account_name = azurerm_storage_account.payloads.name
    account_key  = azurerm_storage_account.payloads.primary_access_key
    container    = azurerm_storage_container.payloads.name
  }

  depends_on = [kubernetes_namespace.cloud_relay]
}
