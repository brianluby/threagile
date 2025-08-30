# AI Threat Model Generation Test Plan

## Overview
This test plan validates the AI-powered threat model generation feature that creates Threagile models from Infrastructure as Code (IaC) files.

## Test Environment Setup

### Prerequisites
1. Threagile built with AI features:
   ```bash
   cd /Users/bluby/personal-repos/threagile-ai-org/threagile
   make all
   ```

2. Test project structure:
   ```
   test-website-demo/
   ├── terraform/
   │   ├── main.tf
   │   ├── database.tf
   │   └── network.tf
   ├── kubernetes/
   │   ├── deployment.yaml
   │   ├── service.yaml
   │   └── ingress.yaml
   └── CLAUDE.md
   ```

## Test Cases

### Test Case 1: Basic Terraform Parsing
**Objective:** Verify basic Terraform infrastructure parsing

**Setup:**
Create `test-website-demo/terraform/main.tf`:
```hcl
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  tags = {
    Name = "WebServer"
  }
}

resource "aws_instance" "api_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.small"
  
  tags = {
    Name = "APIServer"
  }
}

resource "aws_elb" "web_lb" {
  name = "web-loadbalancer"
  
  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port          = 80
    lb_protocol      = "HTTP"
  }
}
```

**Execute:**
```bash
./threagile ai-generate --iac-dirs test-website-demo/terraform/
```

**Expected Results:**
- ✅ Creates `threagile-generated.yaml`
- ✅ Contains 3 technical assets (2 compute instances, 1 load balancer)
- ✅ Creates trust boundary for AWS infrastructure
- ✅ Generates communication link from load balancer to web server

### Test Case 2: Kubernetes Manifest Parsing
**Objective:** Verify Kubernetes manifest parsing

**Setup:**
Create `test-website-demo/kubernetes/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: web
        image: nginx:latest
        ports:
        - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-api
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: api
        image: myapp:latest
        ports:
        - containerPort: 8080
```

Create `test-website-demo/kubernetes/service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
  namespace: production
spec:
  type: LoadBalancer
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: production
spec:
  selector:
    app: backend
  ports:
  - port: 8080
    targetPort: 8080
```

**Execute:**
```bash
./threagile ai-generate --iac-dirs test-website-demo/kubernetes/
```

**Expected Results:**
- ✅ Contains 4 technical assets (2 deployments, 1 load balancer service, internal service)
- ✅ Creates namespace trust boundary "production"
- ✅ Generates service mesh communications between deployments

### Test Case 3: Mixed Infrastructure Parsing
**Objective:** Parse both Terraform and Kubernetes files together

**Setup:**
Add `test-website-demo/terraform/database.tf`:
```hcl
resource "aws_db_instance" "postgres" {
  identifier     = "webapp-db"
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  db_name  = "webapp"
  username = "dbadmin"
  password = "changeme"
}

resource "aws_s3_bucket" "assets" {
  bucket = "webapp-assets"
}
```

**Execute:**
```bash
./threagile ai-generate --iac-dirs test-website-demo/terraform/,test-website-demo/kubernetes/
```

**Expected Results:**
- ✅ Combines assets from both parsers
- ✅ Contains database and storage assets with data assets
- ✅ Multiple trust boundaries (AWS and Kubernetes namespace)

### Test Case 4: Context File Integration
**Objective:** Verify CLAUDE.md context is applied

**Setup:**
Create `test-website-demo/CLAUDE.md`:
```markdown
# Simple E-Commerce Website

This is a demo e-commerce website with the following security requirements:
- PCI DSS compliance required
- GDPR compliance for EU customers
- All payment data must be encrypted

Custom security tags:
- payment-processing
- customer-data
- public-facing
```

**Execute:**
```bash
./threagile ai-generate \
  --iac-dirs test-website-demo/ \
  --context-files test-website-demo/CLAUDE.md
```

**Expected Results:**
- ✅ Model title updated to "Simple E-Commerce Website Threat Model"
- ✅ Security requirements include PCI DSS and GDPR
- ✅ Custom tags added to available tags

### Test Case 5: JSON Output Mode
**Objective:** Test JSON output for CI/CD integration

**Execute:**
```bash
./threagile ai-generate \
  --iac-dirs test-website-demo/ \
  --json
```

**Expected Results:**
- ✅ Outputs JSON summary instead of YAML file
- ✅ JSON contains counts of assets, boundaries, data assets
- ✅ Success flag is true

### Test Case 6: Error Handling - Invalid Directory
**Objective:** Verify error handling for invalid paths

**Execute:**
```bash
./threagile ai-generate --iac-dirs /nonexistent/path/
```

**Expected Results:**
- ✅ Returns error about directory not existing
- ✅ No output file created

### Test Case 7: Error Handling - No IaC Files
**Objective:** Verify handling when no IaC files found

**Setup:**
Create empty directory `test-website-demo/empty/`

**Execute:**
```bash
./threagile ai-generate --iac-dirs test-website-demo/empty/
```

**Expected Results:**
- ✅ Returns error "no infrastructure files found"
- ✅ Clear error message

### Test Case 8: Detailed Mode Error
**Objective:** Verify detailed mode returns proper error

**Execute:**
```bash
./threagile ai-generate --mode detailed --iac-dirs test-website-demo/
```

**Expected Results:**
- ✅ Returns error "detailed mode is not yet implemented"
- ✅ Suggests using simple mode

### Test Case 9: Output Path Specification
**Objective:** Test custom output path

**Execute:**
```bash
./threagile ai-generate \
  --iac-dirs test-website-demo/ \
  --output-file custom-model.yaml
```

**Expected Results:**
- ✅ Creates `custom-model.yaml` instead of default
- ✅ File contains valid threat model

### Test Case 10: Full Integration Test
**Objective:** Generate model and run threat analysis

**Execute:**
```bash
# Generate model
./threagile ai-generate --iac-dirs test-website-demo/

# Run threat analysis
./threagile analyze-model

# Generate report
./threagile analyze-model --generate-report-pdf
```

**Expected Results:**
- ✅ Model generation succeeds
- ✅ Threat analysis identifies risks
- ✅ PDF report generated successfully

## Performance Tests

### Test Case P1: Large Infrastructure
**Objective:** Test with many IaC files

**Setup:** Create 50+ Terraform resources across multiple files

**Execute:**
```bash
time ./threagile ai-generate --iac-dirs large-test/
```

**Expected Results:**
- ✅ Completes within 30 seconds
- ✅ All resources parsed correctly
- ✅ Memory usage reasonable

## Validation Checklist

After each test, validate the generated `threagile-generated.yaml`:

- [ ] Valid YAML syntax
- [ ] All technical assets have required fields (id, title)
- [ ] Trust boundaries contain valid asset references
- [ ] Communication links reference existing assets
- [ ] Data assets have proper classification
- [ ] No duplicate IDs

## Test Execution Log

| Test Case | Date | Result | Notes |
|-----------|------|--------|-------|
| TC1 | | | |
| TC2 | | | |
| TC3 | | | |
| TC4 | | | |
| TC5 | | | |
| TC6 | | | |
| TC7 | | | |
| TC8 | | | |
| TC9 | | | |
| TC10 | | | |

## Known Limitations to Test

1. **Pattern Matching**: Terraform parser uses simple patterns, not full HCL parser
2. **Limited Resources**: Only subset of AWS resources supported
3. **Communication Detection**: Simplified heuristics for service communications
4. **No Merge**: Merge functionality not implemented

## Bug Report Template

**Title:** [Brief description]
**Test Case:** [Which test case revealed the issue]
**Steps to Reproduce:**
1. 
2. 

**Expected:** 
**Actual:** 
**Error Message:** 
**Environment:** macOS, Threagile version from git hash

## Next Testing Phase

After MVP validation:
1. Test with real-world IaC repositories
2. CloudFormation parser testing
3. Pulumi parser testing
4. Performance with 1000+ resources
5. Integration with CI/CD pipelines