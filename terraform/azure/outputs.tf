# Cloud Relay - Azure Outputs

output "resource_group_name" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "cluster_name" {
  description = "AKS cluster name"
  value       = azurerm_kubernetes_cluster.main.name
}

output "cluster_fqdn" {
  description = "AKS cluster FQDN"
  value       = azurerm_kubernetes_cluster.main.fqdn
}

output "kubectl_config_command" {
  description = "Command to configure kubectl"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}"
}

output "database_fqdn" {
  description = "PostgreSQL server FQDN"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "redis_hostname" {
  description = "Redis cache hostname"
  value       = azurerm_redis_cache.main.hostname
}

output "storage_account" {
  description = "Storage account name"
  value       = azurerm_storage_account.payloads.name
}

output "key_vault_name" {
  description = "Key Vault name"
  value       = azurerm_key_vault.main.name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "location" {
  description = "Azure region"
  value       = azurerm_resource_group.main.location
}

output "next_steps" {
  description = "Next steps after Terraform apply"
  value       = <<-EOT

    ============================================
    Cloud Relay Infrastructure Created (Azure)!
    ============================================

    Region: ${azurerm_resource_group.main.location}

    Next steps:

    1. Configure kubectl:
       az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}

    2. Deploy Cloud Relay services:
       helm install cloud-relay ./helm/cloud-relay -n cloud-relay

    3. Get Load Balancer IP:
       kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

    4. Configure DNS to point to Load Balancer

    5. Register with Master Server:
       ./scripts/register-relay.sh --master <MASTER_URL>

    NCA Compliance Note:
    - Data stored in ${azurerm_resource_group.main.location} region
    - All data encrypted at rest and in transit
    - Azure compliance certifications apply

  EOT
}
