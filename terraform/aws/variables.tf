# Cloud Relay - AWS Variables

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
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
  description = "Name of the EKS cluster"
  type        = string
  default     = "offensight-relay"
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

# VPC
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnets" {
  description = "Private subnet CIDRs"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnets" {
  description = "Public subnet CIDRs"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# Node configuration
variable "node_instance_type" {
  description = "EC2 instance type for nodes"
  type        = string
  default     = "t3.medium"
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

variable "node_desired_count" {
  description = "Desired number of nodes"
  type        = number
  default     = 3
}

# Database
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.small"
}

# Redis
variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.small"
}

# Domain
variable "domain_name" {
  description = "Domain name for Cloud Relay (e.g., relay.example.com)"
  type        = string
  default     = ""
}

# Master Server
variable "master_server_endpoint" {
  description = "Master Server endpoint for registration"
  type        = string
  default     = ""
}
