# AI Threat Model Generation - Feature Overview

## 🎯 What It Does

Automatically generates Threagile threat models from your Infrastructure as Code:

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Terraform      │     │                 │     │                  │
│  main.tf        │────▶│   AI Parser     │────▶│  Threat Model    │
│  network.tf     │     │                 │     │  (YAML)          │
└─────────────────┘     │                 │     └──────────────────┘
                        │                 │              │
┌─────────────────┐     │                 │              ▼
│  Kubernetes     │────▶│   Orchestrator  │     ┌──────────────────┐
│  deployment.yml │     │                 │     │  Risk Analysis   │
│  service.yml    │     │                 │     │  PDF Report      │
└─────────────────┘     └─────────────────┘     └──────────────────┘
```

## 🚀 Quick Example

### Input: Terraform File
```hcl
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t2.micro"
}

resource "aws_db_instance" "database" {
  engine = "postgres"
}
```

### Command:
```bash
./threagile ai-generate --iac-dirs ./
```

### Output: Threat Model
```yaml
title: Generated Threat Model
technical_assets:
  aws_instance_web:
    title: "Instance: web"
    type: process
    machine: virtual
  aws_db_instance_database:
    title: "Database: database" 
    type: datastore
    technologies:
    - name: database
```

## 📋 Supported Resources

### Terraform (AWS)
- ✅ EC2 Instances
- ✅ RDS Databases
- ✅ S3 Buckets
- ✅ Load Balancers
- ✅ Lambda Functions
- ✅ VPCs & Security Groups

### Kubernetes
- ✅ Deployments
- ✅ Services
- ✅ Ingress
- ✅ StatefulSets
- ✅ PersistentVolumeClaims
- ✅ ConfigMaps/Secrets

## 🎨 Key Features

1. **Automatic Asset Discovery**
   - Scans directories for .tf and .yaml files
   - Identifies infrastructure components

2. **Trust Boundary Detection**
   - Groups by VPC/Network
   - Kubernetes namespaces
   - Cloud accounts

3. **Communication Inference**
   - Load balancer → Backend connections
   - Service mesh communications
   - Database connections

4. **Context Integration**
   - Reads CLAUDE.md for project info
   - Applies security requirements
   - Adds custom tags

5. **Flexible Output**
   - YAML for Threagile processing
   - JSON for CI/CD integration

## 🧪 Testing

We've prepared comprehensive tests:

1. **Minimal Test** - 1 minute quick check
2. **Full Test Suite** - 10 automated test cases
3. **Demo Project** - Sample e-commerce site

## 🔧 Usage Patterns

### Basic:
```bash
./threagile ai-generate --iac-dirs ./infrastructure/
```

### With Context:
```bash
./threagile ai-generate \
  --iac-dirs ./terraform/,./k8s/ \
  --context-files ./CLAUDE.md
```

### CI/CD Integration:
```bash
./threagile ai-generate --iac-dirs ./ --json > model.json
```

## 📈 Benefits

- **Time Savings**: Minutes instead of hours to create initial model
- **Consistency**: Same parsing rules applied across projects  
- **Coverage**: Won't miss infrastructure components
- **Starting Point**: Generate base model, then refine manually

## 🚧 Current Limitations

- Pattern matching (not full HCL parser)
- Limited to common resource types
- Simple communication detection
- No CloudFormation/Pulumi yet

## 🎯 Next Steps

1. Run the tests to verify it works
2. Try with your real infrastructure
3. Review and enhance the generated model
4. Integrate into your security workflow