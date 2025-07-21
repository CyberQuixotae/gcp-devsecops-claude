# GCP Security Engineering Configurations in Terraform
# This configuration demonstrates comprehensive security controls for GCP

terraform {
  required_version = ">= 1.0"
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
}

  # Recommended: Use remote state
  backend "gcs" {
    # Configure in backend.tf or via terraform init
    # bucket = "your-terraform-state-bucket"
    # prefix = "security/terraform.tfstate"
    # impersonate_service_account = "terraform-sa@your-project.iam.gserviceaccount.com"
  }
}

# Enable required APIs first
resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "cloudkms.googleapis.com",
    "securitycenter.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "pubsub.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com"
  ])

  service            = each.value
  disable_on_destroy = false

  timeouts {
    create = "30m"
    update = "40m"
  }
}

# Provider Configuration
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ============================================================================
# API ENABLEMENT
# ============================================================================


# ============================================================================
# IDENTITY AND ACCESS MANAGEMENT (IAM)
# ============================================================================

# Custom IAM Role with least privilege
resource "google_project_iam_custom_role" "security_viewer" {
  role_id     = "securityViewer"
  title       = "Security Viewer"
  description = "Custom role for security monitoring with minimal permissions"
  permissions = [
    "logging.entries.list",
    "monitoring.metricDescriptors.list",
    "monitoring.timeSeries.list",
    "securitycenter.findings.list",
    "compute.instances.list"
  ]

  depends_on = [google_project_service.required_apis]
}

# Service Account for security operations
resource "google_service_account" "security_sa" {
  account_id   = "security-operations"
  display_name = "Security Operations Service Account"
  description  = "Service account for security monitoring and operations"
}

# IAM binding with conditions - Use member instead of binding to avoid conflicts
resource "google_project_iam_member" "security_member" {
  project = var.project_id
  role    = google_project_iam_custom_role.security_viewer.name
  member  = "serviceAccount:${google_service_account.security_sa.email}"

  condition {
    title       = "Time-based access"
    description = "Only allow access during business hours"
    expression  = "request.time.getHours() >= 9 && request.time.getHours() <= 17"
  }
}

# ============================================================================
# ORGANIZATION POLICY CONSTRAINTS
# Note: Organization policies should be managed at the organization level
# These are examples - actual implementation depends on your org structure
# ============================================================================

# Restrict VM external IP addresses - Project level policy
resource "google_project_organization_policy" "restrict_vm_external_ips" {
  project    = var.project_id
  constraint = "compute.vmExternalIpAccess"

  list_policy {
    deny {
      all = true
    }
  }
}

# Require OS Login - Project level policy
resource "google_project_organization_policy" "require_os_login" {
  project    = var.project_id
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# Restrict service account key creation - Project level policy
resource "google_project_organization_policy" "restrict_sa_key_creation" {
  project    = var.project_id
  constraint = "iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# Domain restricted sharing - Project level policy
resource "google_project_organization_policy" "domain_restricted_sharing" {
  project    = var.project_id
  constraint = "iam.allowedPolicyMemberDomains"

  list_policy {
    allow {
      values = ["example.com"]  # Replace with your domain
    }
  }
}

# ============================================================================
# SECURITY COMMAND CENTER
# ============================================================================

# Enable Security Command Center
resource "google_project_service" "security_center" {
  service = "securitycenter.googleapis.com"
}

# Security Command Center notification config
resource "google_scc_notification_config" "security_notifications" {
  config_id    = "security-notifications"
  organization = var.organization_id
  description  = "Security findings notifications"
  pubsub_topic = google_pubsub_topic.security_notifications.id

  streaming_config {
    filter = "severity=\"HIGH\" OR severity=\"CRITICAL\""
  }

  depends_on = [google_project_service.security_center]
}

# ============================================================================
# CLOUD KMS (KEY MANAGEMENT)
# ============================================================================

# KMS Key Ring
resource "google_kms_key_ring" "security_keyring" {
  name     = "security-keyring"
  location = var.region
}

# Customer Managed Encryption Key (CMEK)
resource "google_kms_crypto_key" "encryption_key" {
  name     = "security-encryption-key"
  key_ring = google_kms_key_ring.security_keyring.id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = "2592000s"  # 30 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# IAM for KMS key - Fixed syntax error
resource "google_kms_crypto_key_iam_binding" "crypto_key_binding" {
  crypto_key_id = google_kms_crypto_key.encryption_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members = [
    "serviceAccount:${google_service_account.security_sa.email}"
  ]
}

# ============================================================================
# NETWORKING SECURITY
# ============================================================================

# VPC with security-focused configuration
resource "google_compute_network" "secure_vpc" {
  name                    = "secure-vpc"
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"
}

# Private subnet
resource "google_compute_subnetwork" "private_subnet" {
  name          = "private-subnet"
  ip_cidr_range = "10.0.1.0/24"
  network       = google_compute_network.secure_vpc.id
  region        = var.region

  # Enable private Google access
  private_ip_google_access = true

  # Enable flow logs for security monitoring
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Cloud NAT for private instances
resource "google_compute_router" "nat_router" {
  name    = "nat-router"
  region  = var.region
  network = google_compute_network.secure_vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "nat-gateway"
  router                            = google_compute_router.nat_router.name
  region                            = var.region
  nat_ip_allocate_option            = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rules with security best practices
resource "google_compute_firewall" "deny_all_ingress" {
  name      = "deny-all-ingress"
  network   = google_compute_network.secure_vpc.name
  priority  = 65534
  direction = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  name      = "allow-internal"
  network   = google_compute_network.secure_vpc.name
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22", "3389", "80", "443"]
  }

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["internal"]
}

resource "google_compute_firewall" "allow_ssh_iap" {
  name      = "allow-ssh-iap"
  network   = google_compute_network.secure_vpc.name
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP source ranges
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ssh-iap"]
}

# ============================================================================
# COMPUTE SECURITY
# ============================================================================

# Secure compute instance template
resource "google_compute_instance_template" "secure_template" {
  name_prefix  = "secure-template-"
  machine_type = "e2-medium"

  # Boot disk with encryption
  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
    disk_encryption_key {
      kms_key_self_link = google_kms_crypto_key.encryption_key.id
    }
  }

  network_interface {
    network    = google_compute_network.secure_vpc.id
    subnetwork = google_compute_subnetwork.private_subnet.id
    # No external IP - using Cloud NAT
  }

  # Security configurations
  service_account {
    email  = google_service_account.security_sa.email
    scopes = ["cloud-platform"]
  }

  # Enable OS Login
  metadata = {
    enable-oslogin = "TRUE"
    # Startup script for security hardening
    startup-script = <<-EOF
      #!/bin/bash
      # Update system
      apt-get update && apt-get upgrade -y

      # Install security tools
      apt-get install -y fail2ban ufw

      # Configure firewall
      ufw --force enable
      ufw default deny incoming
      ufw default allow outgoing

      # Configure fail2ban
      systemctl enable fail2ban
      systemctl start fail2ban

      # Set secure permissions
      chmod 700 /root
      chmod 755 /home
    EOF
  }

  # Confidential computing
  confidential_instance_config {
    enable_confidential_compute = true
  }

  # Shielded VM
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = ["secure-instance", "ssh-iap", "internal"]

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# LOGGING AND MONITORING
# ============================================================================

# Cloud Logging sink for security events
resource "google_logging_project_sink" "security_sink" {
  name        = "security-audit-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.security_logs.id}"

  # Filter for security-relevant logs
  filter = <<-EOF
    (protoPayload.serviceName="compute.googleapis.com" AND
     protoPayload.methodName="v1.compute.instances.insert") OR
    (protoPayload.serviceName="iam.googleapis.com" AND
     protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey") OR
    (protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND
     protoPayload.authenticationInfo.principalEmail!~".*@.*\.gserviceaccount\.com$") OR
    severity>=ERROR
  EOF

  unique_writer_identity = true
}

# Pub/Sub topics for security notifications
resource "google_pubsub_topic" "security_notifications" {
  name = "security-notifications"
}

resource "google_pubsub_topic" "security_logs" {
  name = "security-audit-logs"
}

# Monitoring alert policy for suspicious activity
resource "google_monitoring_alert_policy" "security_alert" {
  display_name = "Security Alert Policy"
  combiner     = "OR"

  conditions {
    display_name = "High severity security findings"

    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"logging.googleapis.com/user/security_events\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 5

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
  }
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Team Email"
  type         = "email"

  labels = {
    email_address = "security-team@example.com"  # Replace with actual email
  }
}

# ============================================================================
# CLOUD ARMOR (WAF)
# ============================================================================

# Cloud Armor security policy
resource "google_compute_security_policy" "security_policy" {
  name        = "security-policy"
  description = "Security policy for web applications"

  # Default rule - allow all traffic
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default rule"
  }

  # Block known bad IPs
  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["192.0.2.0/24"]  # Example malicious IP range
      }
    }
    description = "Block malicious IPs"
  }

  # Rate limiting rule
  rule {
    action   = "rate_based_ban"
    priority = "2000"
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

      ban_threshold {
        count        = 1000
        interval_sec = 300
      }

      ban_duration_sec = 600
    }
    description = "Rate limiting rule"
  }
}

# ============================================================================
# BINARY AUTHORIZATION
# ============================================================================

# Binary Authorization policy
resource "google_binary_authorization_policy" "policy" {
  admission_whitelist_patterns {
    name_pattern = "gcr.io/${var.project_id}/*"
  }

  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"

    require_attestations_by = [
      google_binary_authorization_attestor.attestor.name
    ]
  }

  # Allow Google-provided system images
  admission_whitelist_patterns {
    name_pattern = "gcr.io/google-containers/*"
  }
}

# Binary Authorization attestor
resource "google_binary_authorization_attestor" "attestor" {
  name = "security-attestor"

  attestation_authority_note {
    note_reference = google_container_analysis_note.note.name

    public_keys {
      ascii_armored_pgp_public_key = file("${path.module}/attestor.pub")  # You need to provide this
    }
  }
}

# Container Analysis note
resource "google_container_analysis_note" "note" {
  name = "security-attestation-note"

  attestation_authority {
    hint {
      human_readable_name = "Security Team Attestor"
    }
  }
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "security_service_account_email" {
  description = "Email of the security operations service account"
  value       = google_service_account.security_sa.email
}

output "kms_key_id" {
  description = "ID of the Customer Managed Encryption Key"
  value       = google_kms_crypto_key.encryption_key.id
}

output "vpc_network_id" {
  description = "ID of the secure VPC network"
  value       = google_compute_network.secure_vpc.id
}

output "security_policy_id" {
  description = "ID of the Cloud Armor security policy"
  value       = google_compute_security_policy.security_policy.id
}
