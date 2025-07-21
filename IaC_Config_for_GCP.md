# Google Cloud Environment Setup for Terraform Testing

## Prerequisites

- Google Cloud SDK (gcloud) installed
- Terraform installed (version 1.0+)
- A Google Cloud account with billing enabled

## 1. Initial GCP Setup

### Create a New Project
```bash
# Set variables
export PROJECT_ID="terraform-testing-$(date +%s)"
export BILLING_ACCOUNT_ID="your-billing-account-id"

# Create project
gcloud projects create $PROJECT_ID --name="Terraform Testing Environment"

# Link billing account
gcloud billing projects link $PROJECT_ID --billing-account=$BILLING_ACCOUNT_ID

# Set as default project
gcloud config set project $PROJECT_ID
```

### Enable Required APIs
```bash
# Enable essential APIs for Terraform
gcloud services enable \
    cloudresourcemanager.googleapis.com \
    compute.googleapis.com \
    storage-component.googleapis.com \
    iam.googleapis.com \
    cloudbilling.googleapis.com \
    serviceusage.googleapis.com \
    cloudapis.googleapis.com
```

## 2. Authentication Setup

### Option A: Service Account (Recommended for CI/CD)
```bash
# Create service account
gcloud iam service-accounts create terraform-sa \
    --display-name="Terraform Service Account" \
    --description="Service account for Terraform operations"

# Grant necessary permissions (updated IAM roles)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/compute.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountAdmin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/resourcemanager.projectIamAdmin"

# Create and download key
gcloud iam service-accounts keys create ~/terraform-key.json \
    --iam-account=terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/terraform-key.json
```

### Option B: User Account (For Development)
```bash
# Authenticate with your user account
gcloud auth login
gcloud auth application-default login
```

## 3. Terraform Backend Configuration

### Create GCS Bucket for State
```bash
# Create bucket for Terraform state
export BUCKET_NAME="${PROJECT_ID}-terraform-state"
gsutil mb -p $PROJECT_ID gs://$BUCKET_NAME

# Enable versioning
gsutil versioning set on gs://$BUCKET_NAME

# Set lifecycle policy to manage old versions
cat > lifecycle.json << EOF
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {
        "age": 30,
        "isLive": false
      }
    }
  ]
}
EOF

gsutil lifecycle set lifecycle.json gs://$BUCKET_NAME
```

## 4. Directory Structure - Modify as needed

```
terraform-gcp-testing/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── README.md
│   │   └── terraform.tfvars
│   ├── staging/
│   └── prod/
├── modules/
│   ├── compute/
│   ├── networking/
│   └── storage/
├── tests/
│   ├── unit/
│   └── integration/
└── scripts/
    ├── setup.sh
    └── cleanup.sh
```

## 5. Base Terraform Configuration

### Provider Configuration (main.tf)
```bash
terraform {
  required_version = ">= 1.8"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
  }
  
  backend "gcs" {
    bucket = "your-project-terraform-state"
    prefix = "terraform/state"
  }
}

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
```

### Variables (variables.tf)
```bash
variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}
```

### Sample terraform.tfvars
```bash
project_id  = "your-project-id"
region      = "us-central1"
zone        = "us-central1-a"
environment = "dev"
```

## 6. Testing Framework Setup

### Install Testing Tools (Updated)
```bash
# Install Terratest (Go-based testing)
go mod init terraform-testing
go get github.com/gruntwork-io/terratest/modules/terraform@latest
go get github.com/stretchr/testify/assert@latest

# Install terraform-compliance (Python-based)
pip install terraform-compliance

# Install Checkov for security scanning
pip install checkov

# Install TFLint for linting
curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# Install Infracost for cost estimation
curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh

# Install terraform-docs for documentation
curl -sSLo ./terraform-docs.tar.gz https://terraform-docs.io/dl/v0.16.0/terraform-docs-v0.16.0-$(uname)-amd64.tar.gz
tar -xzf terraform-docs.tar.gz
chmod +x terraform-docs
sudo mv terraform-docs /usr/local/bin/terraform-docs
```

### Sample Test Structure (Go/Terratest)
```go
// tests/integration/terraform_test.go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestTerraformGCPExample(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../../environments/dev",
        Vars: map[string]interface{}{
            "project_id": "your-test-project",
        },
    }
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    // Add your assertions here
    output := terraform.Output(t, terraformOptions, "instance_ip")
    assert.NotEmpty(t, output)
}
```

## 7. Modern Best Practices for Testing

### Environment Isolation
- Use separate projects for different environments
- Implement naming conventions with environment prefixes
- Use Terraform workspaces for state separation
- Enable organization policies for resource constraints

### Workload Identity (Recommended for GKE/Cloud Run)
```bash
# If using GKE, set up Workload Identity instead of service account keys
gcloud iam service-accounts add-iam-policy-binding \
    terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:${PROJECT_ID}.svc.id.goog[default/terraform-ksa]"
```

### Enable Terraform State Locking
```bash
# Add to backend configuration
terraform {
  backend "gcs" {
    bucket                      = "your-project-terraform-state"
    prefix                     = "terraform/state"
    impersonate_service_account = "terraform-sa@your-project.iam.gserviceaccount.com"
  }
}
```

### Resource Tagging (Updated for Google Cloud Labels)
```bash
locals {
  common_labels = {
    environment = var.environment
    project     = var.project_id
    managed_by  = "terraform"
    testing     = "true"
    created_by  = "terraform"
  }
}

resource "google_compute_instance" "example" {
  # ... other configuration
  
  labels = local.common_labels
  
  metadata = {
    terraform-managed = "true"
    environment      = var.environment
  }
}
```

### Cost Management (Updated Budget API)
```bash
# Set up budget alerts with current API
gcloud billing budgets create \
    --billing-account=$BILLING_ACCOUNT_ID \
    --display-name="Terraform Testing Budget" \
    --budget-amount=100.00 \
    --threshold-rules=percent=0.5,percent=0.9,percent=1.0 \
    --filter-projects=$PROJECT_ID \
    --all-updates-rule-monitoring-notification-channels=$NOTIFICATION_CHANNEL \
    --all-updates-rule-pubsub-topic=$PUBSUB_TOPIC
```

## 8. Automation Scripts

### Setup Script (scripts/setup.sh)
```bash
#!/bin/bash
set -e

PROJECT_ID=${1:-"terraform-testing-environment"}
REGION=${2:-"us-central1"}

echo "Setting up GCP environment for Terraform testing..."

# Create project and enable APIs
gcloud projects create $PROJECT_ID
gcloud config set project $PROJECT_ID
gcloud services enable cloudresourcemanager.googleapis.com compute.googleapis.com

# Create state bucket
gsutil mb -p $PROJECT_ID gs://${PROJECT_ID}-terraform-state
gsutil versioning set on gs://${PROJECT_ID}-terraform-state

echo "Environment setup complete!"
echo "Project ID: $PROJECT_ID"
echo "State Bucket: gs://${PROJECT_ID}-terraform-state"
```

### Cleanup Script (scripts/cleanup.sh)
```bash
#!/bin/bash
set -e

PROJECT_ID=$1

if [ -z "$PROJECT_ID" ]; then
    echo "Usage: $0 <project-id>"
    exit 1
fi

echo "Cleaning up resources in project: $PROJECT_ID"

# Destroy Terraform resources
cd environments/dev
terraform destroy -auto-approve

# Delete project (after confirmation)
read -p "Delete project $PROJECT_ID? (y/N): " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    gcloud projects delete $PROJECT_ID
fi
```

## 9. Running Tests

### Manual Testing
```bash
# Initialize and plan
cd environments/dev
terraform init
terraform plan

# Apply with auto-approval for testing
terraform apply -auto-approve

# Run validation
terraform validate
terraform fmt -check
```

### Automated Testing (Comprehensive)
```bash
# Run Go tests with timeout
cd tests/integration
go test -v -timeout 45m -parallel 4

# Run compliance tests
terraform-compliance -f tests/compliance -p environments/dev

# Run security scans
checkov -d environments/dev --framework terraform

# Run linting
tflint environments/dev

# Generate cost estimates
infracost breakdown --path environments/dev

# Validate formatting
terraform fmt -check -recursive

# Run custom validation
terraform validate

# Test with different configurations
terraform plan -var-file="test-scenarios/high-availability.tfvars"
terraform plan -var-file="test-scenarios/minimal.tfvars"
```

## 10. Monitoring and Cleanup

### Set up Monitoring
- Enable Cloud Monitoring for resource usage
- Set up log aggregation for Terraform operations
- Create dashboards for cost tracking

### Automated Cleanup
- Use Cloud Scheduler to run cleanup jobs
- Implement resource lifecycle policies
- Set up alerts for long-running resources

## Security Considerations (Updated)

1. **Least Privilege**: Grant minimal required permissions (avoid Editor role)
2. **Service Account Keys**: Consider Workload Identity instead of downloaded keys
3. **Secret Management**: Use Google Secret Manager for sensitive data
4. **Network Security**: Implement VPC security controls and private Google access
5. **Audit Logging**: Enable Cloud Audit Logs and export to BigQuery
6. **Resource Constraints**: Use organization policies to limit resource creation
7. **State File Security**: Enable encryption at rest and in transit for state files
8. **Multi-factor Authentication**: Require MFA for all administrative accounts
9. **Regular Rotation**: Rotate service account keys and access tokens regularly
10. **Monitoring**: Set up Cloud Security Command Center for security insights

### Advanced IAM Configuration
```bash
# Create custom role for Terraform with minimal permissions
gcloud iam roles create terraform_custom_role \
    --project=$PROJECT_ID \
    --title="Terraform Custom Role" \
    --description="Custom role for Terraform with minimal permissions" \
    --permissions="compute.instances.create,compute.instances.delete,compute.networks.create,storage.buckets.create"

# Use custom role instead of predefined roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:terraform-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="projects/${PROJECT_ID}/roles/terraform_custom_role"
```

## Troubleshooting

### Common Issues
- **Permission Errors**: Check IAM bindings and API enablement
- **State Lock Issues**: Verify GCS bucket permissions
- **Resource Conflicts**: Use unique naming conventions
- **Quota Limits**: Monitor and request quota increases as needed

### Debugging Commands
```bash
# Check current configuration
gcloud config list
terraform version
terraform providers

# Validate configuration
terraform validate
terraform plan -detailed-exitcode

# Debug authentication
gcloud auth list
gcloud projects get-iam-policy $PROJECT_ID
```
