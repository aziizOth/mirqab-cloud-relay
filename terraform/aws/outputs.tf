# Cloud Relay - AWS Outputs

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "kubectl_config_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.aws_region}"
}

output "database_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.db_instance_address
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "s3_bucket" {
  description = "S3 bucket for payloads"
  value       = aws_s3_bucket.payloads.id
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "load_balancer_hostname" {
  description = "Ingress load balancer hostname (available after helm install)"
  value       = "Run: kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
}

output "next_steps" {
  description = "Next steps after Terraform apply"
  value       = <<-EOT

    ============================================
    Cloud Relay Infrastructure Created!
    ============================================

    Next steps:

    1. Configure kubectl:
       ${module.eks.cluster_name != "" ? "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.aws_region}" : ""}

    2. Deploy Cloud Relay services:
       helm install cloud-relay ./helm/cloud-relay -n cloud-relay

    3. Get Load Balancer hostname:
       kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'

    4. Configure DNS to point to Load Balancer

    5. Register with Master Server:
       ./scripts/register-relay.sh --master <MASTER_URL>

  EOT
}
