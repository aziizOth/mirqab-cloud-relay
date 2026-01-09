# =============================================================================
# Mirqab Cloud Relay - GCP Infrastructure
# Phase 2B: Cloud-Based C2 Simulation
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state in production
  # backend "gcs" {
  #   bucket = "mirqab-terraform-state"
  #   prefix = "cloud-relay"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# =============================================================================
# Enable Required APIs
# =============================================================================

resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "dns.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
  ])

  service            = each.key
  disable_on_destroy = false
}

# =============================================================================
# VPC Network
# =============================================================================

resource "google_compute_network" "relay_vpc" {
  name                    = "mirqab-relay-vpc-${var.environment}"
  auto_create_subnetworks = false

  depends_on = [google_project_service.required_apis]
}

resource "google_compute_subnetwork" "relay_subnet" {
  name          = "mirqab-relay-subnet-${var.environment}"
  ip_cidr_range = "10.100.0.0/24"
  region        = var.region
  network       = google_compute_network.relay_vpc.id

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# VPC Connector for Cloud Run
resource "google_vpc_access_connector" "relay_connector" {
  name          = "relay-connector-${var.environment}"
  region        = var.region
  network       = google_compute_network.relay_vpc.name
  ip_cidr_range = "10.100.1.0/28"

  min_instances = 2
  max_instances = 3

  depends_on = [google_project_service.required_apis]
}

# =============================================================================
# Cloud Storage for File Exfiltration Simulation
# =============================================================================

resource "google_storage_bucket" "exfil_bucket" {
  name     = "mirqab-exfil-${var.project_id}-${var.environment}"
  location = var.region

  uniform_bucket_level_access = true

  # Auto-delete old test data to control costs
  lifecycle_rule {
    condition {
      age = 7  # Delete after 7 days
    }
    action {
      type = "Delete"
    }
  }

  versioning {
    enabled = false
  }

  # Prevent accidental deletion in prod
  force_destroy = var.environment != "prod"
}

# =============================================================================
# Secret Manager for Tenant Credentials
# =============================================================================

resource "google_secret_manager_secret" "command_center_key" {
  secret_id = "command-center-signing-key-${var.environment}"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.required_apis]
}

# =============================================================================
# Service Account for Cloud Run Services
# =============================================================================

resource "google_service_account" "relay_service" {
  account_id   = "mirqab-relay-${var.environment}"
  display_name = "Mirqab Cloud Relay Service Account"
}

# Grant storage access
resource "google_storage_bucket_iam_member" "relay_storage" {
  bucket = google_storage_bucket.exfil_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.relay_service.email}"
}

# Grant secret access
resource "google_secret_manager_secret_iam_member" "relay_secrets" {
  secret_id = google_secret_manager_secret.command_center_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.relay_service.email}"
}

# =============================================================================
# Cloud Run - HTTP C2 Simulator
# =============================================================================

resource "google_cloud_run_v2_service" "http_c2" {
  name     = "http-c2-${var.environment}"
  location = var.region

  template {
    service_account = google_service_account.relay_service.email

    scaling {
      min_instance_count = 0  # Scale to zero when idle
      max_instance_count = var.max_instances_per_service
    }

    containers {
      image = "gcr.io/${var.project_id}/http-c2:latest"

      ports {
        container_port = 8080
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "COMMAND_CENTER_URL"
        value = var.command_center_url
      }

      env {
        name = "SIGNING_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.command_center_key.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        startup_cpu_boost = true
      }
    }

    vpc_access {
      connector = google_vpc_access_connector.relay_connector.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    timeout = "60s"
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [google_project_service.required_apis]
}

# Allow unauthenticated access (agents connect here)
resource "google_cloud_run_v2_service_iam_member" "http_c2_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.http_c2.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# =============================================================================
# Cloud DNS for DNS C2 Simulator
# =============================================================================

resource "google_dns_managed_zone" "c2_zone" {
  name        = var.dns_zone_name
  dns_name    = "${var.dns_domain}."
  description = "DNS zone for C2 simulation"

  visibility = "public"

  depends_on = [google_project_service.required_apis]
}

# =============================================================================
# Cloud Armor Security Policy
# =============================================================================

resource "google_compute_security_policy" "relay_policy" {
  count = var.enable_cloud_armor ? 1 : 0
  name  = "mirqab-relay-policy-${var.environment}"

  # Default: deny
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny rule"
  }

  # Allow configured source ranges
  dynamic "rule" {
    for_each = length(var.allowed_source_ranges) > 0 ? [1] : []
    content {
      action   = "allow"
      priority = "1000"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = var.allowed_source_ranges
        }
      }
      description = "Allow configured source ranges"
    }
  }

  # Rate limiting
  rule {
    action   = "rate_based_ban"
    priority = "900"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      ban_duration_sec = 300
    }
    description = "Rate limit: 100 req/min per IP"
  }
}

# =============================================================================
# Budget Alert
# =============================================================================

resource "google_billing_budget" "relay_budget" {
  billing_account = data.google_billing_account.account.id
  display_name    = "Mirqab Cloud Relay Budget - ${var.environment}"

  budget_filter {
    projects = ["projects/${var.project_id}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.monthly_budget_usd)
    }
  }

  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.9
  }
  threshold_rules {
    threshold_percent = 1.0
  }
}

data "google_billing_account" "account" {
  display_name = "My Billing Account"
  open         = true
}

# =============================================================================
# Monitoring Dashboard
# =============================================================================

resource "google_monitoring_dashboard" "relay_dashboard" {
  dashboard_json = jsonencode({
    displayName = "Mirqab Cloud Relay - ${var.environment}"
    gridLayout = {
      columns = 2
      widgets = [
        {
          title = "HTTP C2 Request Count"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"http-c2-${var.environment}\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_RATE"
                  }
                }
              }
            }]
          }
        },
        {
          title = "Cloud Run Instance Count"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"cloud_run_revision\""
                }
              }
            }]
          }
        }
      ]
    }
  })
}
