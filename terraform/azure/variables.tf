# Cloud Relay - Azure Variables
# Includes Middle East regions for NCA compliance

variable "location" {
  description = "Azure region"
  type        = string
  default     = "uaenorth"  # Dubai - closest to Saudi Arabia

  # Available Middle East regions:
  # - uaenorth (Dubai) - Recommended for Saudi/GCC
  # - uaecentral (Abu Dhabi)
  # - qatarcentral (Qatar)
  # - israelcentral (Israel)
  # Note: Saudi Arabia region coming soon from Azure
}

variable "environment" {
  description = "Environment name (production, staging, dev)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "dev"], var.environment)
    error_message = "Environment must be production, staging, or dev."
  }
}

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
  default     = "offensight-relay"
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

# Network
variable "vnet_cidr" {
  description = "CIDR block for VNet"
  type        = string
  default     = "10.0.0.0/8"
}

variable "aks_subnet_cidr" {
  description = "CIDR for AKS subnet"
  type        = string
  default     = "10.240.0.0/16"
}

variable "database_subnet_cidr" {
  description = "CIDR for database subnet"
  type        = string
  default     = "10.241.0.0/24"
}

variable "redis_subnet_cidr" {
  description = "CIDR for Redis subnet"
  type        = string
  default     = "10.241.1.0/24"
}

# Node configuration
variable "node_vm_size" {
  description = "VM size for nodes"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "node_count" {
  description = "Initial number of nodes"
  type        = number
  default     = 3
}

variable "node_min_count" {
  description = "Minimum number of nodes"
  type        = number
  default     = 2
}

variable "node_max_count" {
  description = "Maximum number of nodes"
  type        = number
  default     = 10
}

# Database
variable "db_sku" {
  description = "PostgreSQL SKU"
  type        = string
  default     = "B_Standard_B1ms"  # Burstable for cost savings
}

# Redis
variable "redis_capacity" {
  description = "Redis cache capacity"
  type        = number
  default     = 0  # 250MB
}

variable "redis_family" {
  description = "Redis cache family"
  type        = string
  default     = "C"  # Basic/Standard
}

variable "redis_sku" {
  description = "Redis cache SKU"
  type        = string
  default     = "Basic"
}

# Domain
variable "domain_name" {
  description = "Domain name for Cloud Relay"
  type        = string
  default     = ""
}

# Master Server
variable "master_server_endpoint" {
  description = "Master Server endpoint for registration"
  type        = string
  default     = ""
}
