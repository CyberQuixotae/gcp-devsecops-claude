# Variables with validation
variable "project_id" {
  description = "GCP Project ID"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be a valid GCP project identifier (6-30 characters, lowercase letters, numbers, and hyphens)."
  }
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
  validation {
    condition = contains([
      "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
      "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
      "asia-east1", "asia-northeast1", "asia-southeast1", "australia-southeast1"
    ], var.region)
    error_message = "Region must be a valid GCP region."
  }
}

variable "zone" {
  description = "GCP Zone"
  type        = string
  default     = "us-central1-a"
}

variable "organization_id" {
  description = "GCP Organization ID"
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "Organization ID must be numeric."
  }
}

variable "organization_domain" {
  description = "Organization domain for domain-restricted sharing"
  type        = string
  default     = "example.com"
}

variable "security_team_email" {
  description = "Security team email for notifications"
  type        = string
  default     = "security-team@example.com"
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_team_email))
    error_message = "Security team email must be a valid email address."
  }
}

variable "private_subnet_cidr" {
  description = "CIDR range for private subnet"
  type        = string
  default     = "10.0.1.0/24"
  validation {
    condition     = can(cidrhost(var.private_subnet_cidr, 0))
    error_message = "Private subnet CIDR must be a valid CIDR block."
  }
}

variable "compute_machine_type" {
  description = "Machine type for compute instances"
  type        = string
  default     = "e2-medium"
}

variable "compute_boot_image" {
  description = "Boot image for compute instances"
  type        = string
  default     = "debian-cloud/debian-11"
}

variable "kms_key_rotation_period" {
  description = "KMS key rotation period in seconds"
  type        = string
  default     = "2592000s"  # 30 days
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default = {
    environment = "production"
    team        = "security"
    managed-by  = "terraform"
  }
}

variable "enable_confidential_computing" {
  description = "Enable Confidential Computing on VMs"
  type        = bool
  default     = true
}

variable "enable_shielded_vms" {
  description = "Enable Shielded VMs"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_sampling_rate" {
  description = "VPC Flow Logs sampling rate (0.1 to 1.0)"
  type        = number
  default     = 0.5
  validation {
    condition     = var.vpc_flow_logs_sampling_rate >= 0.1 && var.vpc_flow_logs_sampling_rate <= 1.0
    error_message = "VPC Flow Logs sampling rate must be between 0.1 and 1.0."
  }
}
