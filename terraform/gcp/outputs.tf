# =============================================================================
# Mirqab Cloud Relay - Terraform Outputs
# =============================================================================

output "http_c2_url" {
  description = "URL of the HTTP C2 service"
  value       = google_cloud_run_v2_service.http_c2.uri
}

output "exfil_bucket_name" {
  description = "Name of the exfiltration bucket"
  value       = google_storage_bucket.exfil_bucket.name
}

output "dns_zone_name_servers" {
  description = "Name servers for the C2 DNS zone"
  value       = google_dns_managed_zone.c2_zone.name_servers
}

output "service_account_email" {
  description = "Service account email for Cloud Run services"
  value       = google_service_account.relay_service.email
}

output "vpc_network_id" {
  description = "VPC network ID"
  value       = google_compute_network.relay_vpc.id
}

output "region" {
  description = "Deployed region"
  value       = var.region
}
