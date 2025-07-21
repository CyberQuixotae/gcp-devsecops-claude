GCP Security Engineering with Terraform

This repository contains Terraform configurations for implementing comprehensive security controls on Google Cloud Platform (GCP). The configuration follows security best practices and implements defense-in-depth strategies.

## 🔐Security Features Implemented

- **Identity & Access Management (IAM)** - Custom roles, service accounts, conditional access
- **Organization Policies** - Security constraints and compliance controls
- **Key Management** - Customer-managed encryption keys (CMEK) with rotation
- **Network Security** - Private VPCs, Cloud NAT, restrictive firewall rules
- **Computer Security** - Shielded VMs, Confidential Computing, OS Login
- **Monitoring & Alerting** -  Security event logging, Cloud Monitoring alerts
- **Application Security** -  Cloud Armor WAF, Binary Authorization
- **Compliance** -  Audit logging, policy enforcement

## 📋 Prerequisites

1. **GCP Organization** - Required for Security Command Center
2. **Billing Account** - With appropriate permissions
3. **Terraform** - Version 1.0 or higher
4. **gcloud CLI** - For authentication
5. **GPG** - For Binary Authorization (if enabled)

## Required Permissions

You need the following IAM roles to deploy this configuration.

- Organization-level roles (if using org policies):
```
roles/resourcemanager.organizationAdmin
roles/orgpolicy.policyAdmin
```
- Project-level roles:

```roles/owner```

- OR the following specific roles:

```
roles/compute.admin
roles/iam.admin
roles/cloudkms.admin
roles/securitycenter.admin
roles/binaryauthorization.admin
roles/logging.admin
roles/monitoring.admin
roles/pubsub.admin
```

## GCP Project Setup

    Create a new GCP project or use an existing one
    Enable billing on the project
    Note your Organization ID (if using organization policies)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd gcp-security-terraform
```

### 2. Authenticate with GCP

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud auth application-default login
```

### 3. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your specific values
```

### 4. Generate GPG Key (for Binary Authorization)

```bash
# Generate GPG key pair
gpg --full-generate-key
# Export public key
gpg --armor --export YOUR_KEY_ID > attestor-public-key.pgp
```

### 5. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

## 📁 File Structure

```bash
.
├── main.tf                    # Main Terraform configuration
├── terraform.tfvars          # Your environment variables (DO NOT COMMIT)
├── terraform.tfvars.example  # Template for variables
├── README.md                 # This file
├── .gitignore                # Git ignore file
└── attestor.pub              # Binary Authorization public key (create this)
```


## 🏗️ Architecture Overview

### Network Architecture

    Private VPC: No auto-subnets, regional routing
    Private Subnet: Internal IPs only with Private Google Access
    Cloud NAT: Outbound internet access for private instances
    Firewall Rules: Restrictive rules with IAP integration

### Security Architecture

    IAM: Least privilege with custom roles and conditional access
    Encryption: CMEK encryption for all data at rest
    Monitoring: Comprehensive logging and alerting
    Compliance: Organization policies and audit trails

### Compute Architecture

    Shielded VMs: Secure boot, vTPM, integrity monitoring
    Confidential Computing: Encrypted memory processing
    OS Login: Centralized SSH key management
    No External IPs: All instances are private

## 🔍 Monitoring and Alerting

### The configuration creates several monitoring components:

    High severity security findings
    Suspicious authentication activity
    Resource creation anomalies
    Policy violations

### Log Sinks:

    Security audit logs to Pub/Sub
    Failed authentication attempts
    Administrative actions
    Resource modifications

### Notification Channels:

    Email notifications to security team
    Pub/Sub topics for integration
    Cloud Monitoring dashboards

## 🛡️ Security Hardening

### Organization Policies Applied:

    Restrict VM external IP addresses
    Require OS Login on all instances
    Block service account key creation
    Domain-restricted sharing

### Compute Hardening:

    Confidential Computing enabled
    Shielded VM features enabled
    Custom boot scripts for OS hardening
    Automatic security updates

### Network Hardening:

    VPC Flow Logs enabled
    Private Google Access only
    Restrictive firewall rules
    Cloud NAT for outbound only

## 📊 Cost Considerations

### High-Cost Resources:

    Cloud KMS: Key operations and storage
    VPC Flow Logs: Storage and processing
    Confidential Computing: Premium pricing
    Cloud Armor: Request processing fees

### Cost Optimization Tips:

    Adjust VPC Flow Logs sampling rate
    Use sustained use discounts
    Right-size compute instances
    Monitor KMS key usage

## 🔧 Customization

### Adding New Regions

### Add to terraform.tfvars:
```
secondary_region = "us-east1"
secondary_zone = "us-east1-a"
```

### Custom Firewall Rules
```yaml
# Add custom rules to the firewall section
resource "google_compute_firewall" "custom_rule" {
  name    = "allow-custom-app"
  network = google_compute_network.secure_vpc.name
  
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
  
  source_tags = ["web-servers"]
  target_tags = ["app-servers"]
}
```
### Additional Monitoring

Extend monitoring with custom metrics:

```yaml
resource "google_monitoring_alert_policy" "custom_alert" {
  display_name = "Custom Security Alert"
  # ... configuration
}
```

## 🚨 Troubleshooting

### API Not Enabled Error

```bash
# Enable required APIs manually
gcloud services enable compute.googleapis.com
gcloud services enable cloudkms.googleapis.com
```

### Insufficient Permissions

```bash
# Check current permissions
gcloud auth list
gcloud projects get-iam-policy PROJECT_ID
```

### Organization Policy Conflicts

```bash
# Check existing policies
gcloud resource-manager org-policies list --organization=ORG_ID
```


### Resource Quotas

```bash
# Check quotas
gcloud compute project-info describe --project=PROJECT_ID
```
### Terraform State Issues

```bash
# Import existing resources
terraform import google_project.project PROJECT_ID

# Refresh state
terraform refresh

# Force unlock (if needed)
terraform force-unlock LOCK_ID
```

## 🔄 Maintenance

###Regular Tasks:

    Review and rotate KMS keys
    Update organization policies
    Review firewall rules and access logs
    Update compute images and templates
    Review IAM permissions and service accounts

### Security Reviews:

    Quarterly access reviews
    Monthly policy compliance checks
    Weekly log analysis
    Daily alert monitoring

## 📚 Additional Resources:

    GCP Security Best Practices
    Terraform Google Provider Documentation
    GCP Security Command Center
    Cloud KMS Documentation

## 🤝 Contributing:

    Fork the repository
    Create a feature branch
    Make your changes
    Test thoroughly
    Create a pull request

## ⚠️ Security Considerations

    Never commit terraform.tfvars - contains sensitive information
    Use separate environments - dev/staging/prod isolation
    Regular security reviews - audit access and permissions
    Monitor all changes - track infrastructure modifications
    Test disaster recovery - verify backup and restore procedures

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

    Check the troubleshooting section
    Review GCP documentation
    Create an issue in this repository
    Contact your security team

## ⚠️ Important Security Notice: This configuration creates production-grade security controls. Ensure you understand all implications before deploying in production environments.
