# Variables with validation and descriptions

variable "project_id" {
  description = "GCP Project ID"
  type        = string
  validation {
    condition     = length(var.project_id) > 0 && can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, start with lowercase letter, contain only lowercase letters, numbers, and hyphens."
  }
}


variable "organization_id" {
  description = "GCP Organization ID (numeric)"
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "Organization ID must be numeric."
  }
}

variable "billing_account" {
  description = "Billing account ID"
  type        = string
  validation {
    condition     = can(regex("^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$", var.billing_account))
    error_message = "Billing account must be in format XXXXXX-XXXXXX-XXXXXX."
  }
}

variable "company_name" {
  description = "Company name for resource naming (alphanumeric only)"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9]+$", var.company_name))
    error_message = "Company name must contain only alphanumeric characters."
  }
}

variable "region" {
  description = "Primary GCP region"
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
  description = "Primary GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "admin_users" {
  description = "List of admin user emails"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for email in var.admin_users : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All admin users must be valid email addresses."
  }
}

variable "security_email" {
  description = "Email address for security alerts"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_email))
    error_message = "Security email must be a valid email address."
  }
}

variable "enable_security_center" {
  description = "Enable Security Command Center (requires premium subscription - $1000+/month)"
  type        = bool
  default     = false
}

variable "enable_binary_auth" {
  description = "Enable Binary Authorization for container security"
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Enable Cloud Monitoring alerts"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable security logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3653
    error_message = "Log retention must be between 1 and 3653 days."
  }
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs (can be expensive for high traffic)"
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR block for VPC subnet"
  type        = string
  default     = "10.0.1.0/24"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "enable_oslogin" {
  description = "Enable OS Login for centralized SSH key management"
  type        = bool
  default     = true
}

variable "kms_rotation_period" {
  description = "KMS key rotation period in seconds (default: 90 days)"
  type        = string
  default     = "7776000s"
}
