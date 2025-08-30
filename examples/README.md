# Threagile AI Examples

This directory contains example Infrastructure as Code (IaC) files for testing Threagile's AI-powered threat model generation.

## Structure

```
examples/
├── terraform/
│   └── simple-web-app/     # Basic AWS web application
├── kubernetes/
│   └── basic-deployment/   # K8s microservices app
└── expected-outputs/       # Expected threat models
```

## Running Examples

### Terraform Example

The `terraform/simple-web-app/` contains a basic 3-tier web application on AWS:
- Application Load Balancer (Internet-facing)
- EC2 Web Server
- RDS PostgreSQL Database
- S3 Bucket for static assets
- VPC with public and private subnets

Generate threat model:
```bash
threagile ai-generate --iac-dirs examples/terraform/simple-web-app/
```

### Kubernetes Example

The `kubernetes/basic-deployment/` contains a microservices application:
- Frontend (Nginx)
- Backend API (Node.js)
- PostgreSQL Database
- Ingress for external access
- Namespace isolation

Generate threat model:
```bash
threagile ai-generate --iac-dirs examples/kubernetes/basic-deployment/
```

### Combined Example

Generate a threat model from both:
```bash
threagile ai-generate --iac-dirs examples/terraform/,examples/kubernetes/
```

## Expected Results

### Trust Boundaries
- **Terraform**: VPC boundary, public/private subnet separation
- **Kubernetes**: Namespace boundary (simple-app)

### Technical Assets
- **Terraform**: ALB, EC2 instance, RDS database, S3 bucket
- **Kubernetes**: Frontend pods, Backend pods, PostgreSQL StatefulSet, Ingress

### Communications
- **Terraform**: ALB → EC2, EC2 → RDS
- **Kubernetes**: Ingress → Frontend/Backend, Backend → PostgreSQL

### Data Assets
- **Terraform**: Database data, S3 objects
- **Kubernetes**: Database credentials (Secret), Application config (ConfigMap)

## Testing AI Features

1. **Simple Mode Test**:
   ```bash
   threagile ai-generate --mode simple --iac-dirs examples/
   ```

2. **With Context File**:
   Create a `CLAUDE.md` in the examples directory:
   ```markdown
   # Example Web Application
   This is a sample e-commerce application.
   
   ## Security Requirements
   - PCI-DSS compliance required
   - Data encryption at rest
   - HTTPS only
   ```
   
   Then run:
   ```bash
   threagile ai-generate --context-files examples/CLAUDE.md --iac-dirs examples/
   ```

3. **JSON Output**:
   ```bash
   threagile ai-generate --iac-dirs examples/ --json
   ```

## Validation

After generation, analyze the model:
```bash
threagile analyze-model
```

This should identify risks such as:
- Internet-facing assets
- Unencrypted communications
- Missing network segmentation
- Hardcoded credentials (in K8s example)