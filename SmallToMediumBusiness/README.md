# GCP Security Engineering Configuration for SMB

This Terraform configuration provides enterprise-grade security controls for Google Cloud Platform, specifically designed for small-to-medium businesses (SMBs). It implements security best practices while maintaining cost-effectiveness and operational simplicity.

This document was generated with help from Claude Sonnet 4 and audited/modified by cyberquixote.

# SECURITY WARNING: Never commit terraform.tfvars to version control!
# Add terraform.tfvars to your .gitignore file

## 🔐 Security Features Included

### Core Security Services
- **Cloud KMS** - Customer-managed encryption keys with automatic rotation
- **IAM Security** - Custom roles and least-privilege access control
- **Secret Manager** - Secure storage for sensitive data
- **Binary Authorization** - Container image security (optional)
- **Security Command Center** - Threat detection (optional, premium feature)

### Monitoring & Alerting
- **Cloud Logging** - Centralized security event logging
- **Cloud Monitoring** - Automated alerts for security events
- **Email Notifications** - Real-time security alerts
- **Log Retention** - Configurable retention with lifecycle policies

### Network Security
- **Hardened VPC** - Secure network configuration
- **Firewall Rules** - Deny-by-default security model
- **Identity-Aware Proxy** - Secure access without VPN
- **Cloud NAT** - Secure outbound internet access
- **Flow Logs** - Network traffic monitoring (optional)

### Infrastructure Security
- **Shielded VMs** - Hardware-level security features
- **Encrypted Disks** - Customer-managed encryption
- **OS Login** - Centralized SSH key management
- **Security Hardening** - Secure VM templates

## 💰 Cost Considerations for SMBs

### Included (Standard Pricing)
- Cloud KMS: ~$1/month per key
- Secret Manager: ~$0.06 per secret per month
- Cloud Logging: First 50GB/month free
- Cloud Monitoring: Free tier available
- Binary Authorization: No additional cost

### Optional (Premium Features)
- **Security Command Center Premium**: $1,000+/month (disabled by default)
- **Flow Logs**: Can be expensive for high-traffic networks (disabled by default)
- **Extended Log Retention**: Additional storage costs

## 📋 Prerequisites

1. **GCP Organization** - Required for Security Command Center
2. **Billing Account** - With appropriate permissions
3. **Terraform** - Version 1.0 or higher
4. **gcloud CLI** - For authentication
5. **GPG** - For Binary Authorization (if enabled)

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

## ⚙️ Configuration Options

### terraform.tfvars Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `project_id` | GCP Project ID | Yes | - |
| `organization_id` | GCP Organization ID | Yes | - |
| `billing_account` | Billing Account ID | Yes | - |
| `company_name` | Company name for resources | Yes | - |
| `region` | Primary GCP region | No | us-central1 |
| `zone` | Primary GCP zone | No | us-central1-a |
| `admin_users` | List of admin users | No | [] |
| `enable_security_center` | Enable Security Command Center | No | false |
| `enable_binary_auth` | Enable Binary Authorization | No | true |
| `enable_monitoring` | Enable monitoring alerts | No | true |
| `enable_logging` | Enable security logging | No | true |
| `log_retention_days` | Log retention period | No | 30 |
| `enable_flow_logs` | Enable VPC flow logs | No | false |
| `security_email` | Email for security alerts | Yes | - |

### Cost Optimization Settings

For budget-conscious SMBs, consider these settings:

```yaml
# Disable expensive features
enable_security_center = false
enable_flow_logs = false

# Reduce log retention
log_retention_days = 30

# Use smaller VM types
vm_machine_type = "e2-micro"
```

## 🔧 Post-Deployment Configuration

### 1. Verify Security Settings

```bash
# Check IAM policies
gcloud projects get-iam-policy YOUR_PROJECT_ID

# Verify KMS keys
gcloud kms keys list --location=us-central1 --keyring=YOUR_COMPANY-security-keyring

# Check firewall rules
gcloud compute firewall-rules list
```

### 2. Configure Monitoring

1. Go to Cloud Monitoring console
2. Verify notification channels are configured
3. Test alert policies
4. Set up additional custom metrics if needed

### 3. Set Up Binary Authorization (if enabled)

```bash
# Create attestation
gcloud container binauthz attestations sign-and-create \
    --attestor=YOUR_COMPANY-security-attestor \
    --signature-file=signature.sig \
    --public-key-id=security-attestor-key \
    --validate
```

## 📊 Monitoring and Alerts

### Default Alert Policies

1. **IAM Policy Changes** - Triggers on any IAM policy modifications
2. **Failed Login Attempts** - Alerts on suspicious login patterns
3. **Unusual Network Activity** - Monitors for anomalous traffic
4. **Resource Creation** - Tracks new resource deployments

### Log Analysis

Security logs are stored in Cloud Storage with the following structure:
- **Location**: `gs://YOUR_PROJECT_ID-security-logs/`
- **Retention**: Configurable (default 30 days)
- **Format**: JSON with structured fields

## 🛡️ Security Best Practices

### Access Control
- Use IAM conditions for fine-grained access
- Implement just-in-time access where possible
- Regular access reviews and cleanup
- Enable MFA for all admin accounts

### Network Security
- Use Private Google Access for internal resources
- Implement network segmentation
- Regular firewall rule audits
- Monitor network traffic patterns

### Data Protection
- Encrypt all data at rest and in transit
- Use Secret Manager for sensitive data
- Implement proper backup strategies
- Regular security assessments

## 🔄 Maintenance

### Monthly Tasks
- Review security alerts and logs
- Update Terraform configurations
- Rotate service account keys
- Review and update firewall rules

### Quarterly Tasks
- Security assessment and penetration testing
- Review and update IAM policies
- Cost optimization review
- Disaster recovery testing

## 🆘 Troubleshooting

### Common Issues

1. **API Not Enabled Error**
   ```bash
   gcloud services enable SERVICE_NAME
   ```

2. **Insufficient Permissions**
   - Verify billing account permissions
   - Check organization-level IAM roles
   - Ensure service account has required roles

3. **KMS Key Access Issues**
   - Verify service account has `cloudkms.cryptoKeyEncrypterDecrypter` role
   - Check key ring location matches resource location

4. **Binary Authorization Failures**
   - Verify GPG key is correctly formatted
   - Check attestor configuration
   - Ensure container images are properly signed

### Getting Help

- Check Terraform logs: `terraform apply -debug`
- Review GCP audit logs in Cloud Logging
- Consult GCP documentation: https://cloud.google.com/docs
- File issues in the repository

## 📈 Scaling for Growth

As your business grows, consider these enhancements:

1. **Multi-region deployment** for high availability
2. **Advanced monitoring** with custom metrics
3. **Automated incident response** with Cloud Functions
4. **Compliance automation** with Config Connector
5. **Advanced threat detection** with Chronicle SIEM

## 🔒 Security Contacts

- **Security Team**: security@yourcompany.com
- **Emergency Contact**: +1-XXX-XXX-XXXX
- **Incident Response**: Follow your incident response plan

## 📚 Additional Resources

- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Terraform GCP Provider Documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Cloud Security Command Center](https://cloud.google.com/security-command-center)
- [Binary Authorization Documentation](https://cloud.google.com/binary-authorization)

---

**Note**: This configuration is designed for SMBs and may need customization for larger enterprises. Always review and test in a non-production environment first. Or don't at your own peril.

---


