# Quick Start: AI Threat Model Generation

This guide shows how to quickly generate a threat model from your Infrastructure as Code files.

## 1. Build Threagile with AI Features

```bash
cd /Users/bluby/personal-repos/threagile-ai-org/threagile
make all
```

## 2. Basic Usage

### Generate from a single directory:
```bash
./threagile ai-generate --iac-dirs ./my-infrastructure/
```

### Generate from multiple directories:
```bash
./threagile ai-generate --iac-dirs ./terraform/,./kubernetes/,./cloudformation/
```

### Include context from CLAUDE.md:
```bash
./threagile ai-generate \
  --iac-dirs ./my-project/ \
  --context-files ./my-project/CLAUDE.md
```

### Generate JSON output for CI/CD:
```bash
./threagile ai-generate --iac-dirs ./infrastructure/ --json
```

## 3. Example with Your Website Demo

If you have a website demo with infrastructure files:

```bash
# Basic generation
./threagile ai-generate --iac-dirs /path/to/your/website-demo/

# This creates threagile-generated.yaml
# Now analyze it for threats
./threagile analyze-model

# Generate a PDF report
./threagile analyze-model --generate-report-pdf
```

## 4. Supported Infrastructure Files

### Terraform (.tf)
- AWS resources (EC2, RDS, S3, ELB, Lambda)
- Basic VPC and security groups

### Kubernetes (.yaml, .yml)
- Deployments, StatefulSets, DaemonSets
- Services (LoadBalancer, ClusterIP)
- Ingress controllers
- ConfigMaps and Secrets
- PersistentVolumeClaims

### Coming Soon
- CloudFormation
- Pulumi
- Azure ARM templates
- Google Cloud Deployment Manager

## 5. Understanding the Output

The generated `threagile-generated.yaml` contains:

- **Technical Assets**: Your infrastructure components (servers, databases, etc.)
- **Trust Boundaries**: Network segments, namespaces, cloud accounts
- **Communication Links**: How components talk to each other
- **Data Assets**: Identified data stores and their classifications

## 6. Tips for Better Results

1. **Use descriptive names** in your IaC files
2. **Add tags** to resources for better classification
3. **Include CLAUDE.md** with project context and security requirements
4. **Organize IaC files** by environment or component

## 7. Troubleshooting

### No assets found?
- Check file extensions (.tf, .yaml, .yml)
- Ensure files contain valid resource definitions
- Try with --iac-dirs pointing to parent directory

### Missing communications?
- The simple mode uses heuristics
- Manually add critical flows in the generated YAML

### Need more detail?
- Detailed mode coming soon
- For now, use generated model as starting point

## 8. Example CLAUDE.md

Create a `CLAUDE.md` in your project root:

```markdown
# My Web Application

E-commerce platform handling payment data.

Security requirements:
- PCI DSS compliance
- Data encryption at rest
- HTTPS only

Custom tags:
- payment-processing
- customer-data
```

This context will be automatically included in the threat model.