# =============================================================================
# Mirqab Cloud Relay - GCP Variables
# =============================================================================

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region (Saudi Arabia)"
  type        = string
  default     = "me-central2"  # Dammam, Saudi Arabia
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "command_center_url" {
  description = "URL of Command Center for callback validation"
  type        = string
}

variable "allowed_tenant_ids" {
  description = "List of tenant IDs allowed to use this relay"
  type        = list(string)
  default     = []
}

# Cost controls
variable "max_instances_per_service" {
  description = "Maximum Cloud Run instances per service"
  type        = number
  default     = 5
}

variable "monthly_budget_usd" {
  description = "Monthly budget alert threshold in USD"
  type        = number
  default     = 100
}

# Security
variable "enable_cloud_armor" {
  description = "Enable Cloud Armor WAF"
  type        = bool
  default     = true
}

variable "allowed_source_ranges" {
  description = "CIDR ranges allowed to access relay (empty = all)"
  type        = list(string)
  default     = []
}

# DNS
variable "dns_zone_name" {
  description = "Name for the Cloud DNS zone"
  type        = string
  default     = "mirqab-c2-zone"
}

variable "dns_domain" {
  description = "Domain for DNS C2 simulation"
  type        = string
  default     = "c2.mirqab.local"
}
