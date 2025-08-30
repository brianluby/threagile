#!/bin/bash

# Setup script for AI threat model generation testing

echo "Setting up test website demo..."

# Create directory structure
mkdir -p test-website-demo/terraform
mkdir -p test-website-demo/kubernetes
mkdir -p test-website-demo/empty

# Create Terraform files
cat > test-website-demo/terraform/main.tf << 'EOF'
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
EOF

cat > test-website-demo/terraform/database.tf << 'EOF'
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
  
  tags = {
    Name = "Asset Storage"
  }
}
EOF

cat > test-website-demo/terraform/network.tf << 'EOF'
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_security_group" "web" {
  name        = "web-security-group"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
EOF

# Create Kubernetes files
cat > test-website-demo/kubernetes/deployment.yaml << 'EOF'
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
EOF

cat > test-website-demo/kubernetes/service.yaml << 'EOF'
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
EOF

cat > test-website-demo/kubernetes/ingress.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webapp-ingress
  namespace: production
spec:
  rules:
  - host: webapp.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend-service
            port:
              number: 8080
EOF

cat > test-website-demo/kubernetes/namespace.yaml << 'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: production
EOF

# Create context file
cat > test-website-demo/CLAUDE.md << 'EOF'
# Simple E-Commerce Website

This is a demo e-commerce website with the following security requirements:
- PCI DSS compliance required
- GDPR compliance for EU customers
- All payment data must be encrypted

Custom security tags:
- payment-processing
- customer-data
- public-facing

## Architecture Overview

The application consists of:
- Frontend web servers behind a load balancer
- Backend API servers
- PostgreSQL database for customer data
- S3 bucket for static assets
- Kubernetes cluster for container orchestration
EOF

echo "Test environment created successfully!"
echo ""
echo "Directory structure:"
tree test-website-demo/

echo ""
echo "To run the first test:"
echo "  ./threagile ai-generate --iac-dirs test-website-demo/terraform/"
echo ""
echo "See TEST_PLAN.md for complete test cases"