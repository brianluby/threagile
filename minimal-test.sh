#!/bin/bash

# Minimal test to verify AI generation works

echo "Creating minimal test case..."

# Create test directory
mkdir -p minimal-test

# Create a simple Terraform file
cat > minimal-test/main.tf << 'EOF'
resource "aws_instance" "test" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
  
  tags = {
    Name = "MinimalTest"
  }
}
EOF

echo "Running AI threat model generation..."
./threagile ai-generate --iac-dirs minimal-test/

if [ -f "threagile-generated.yaml" ]; then
    echo "✅ Success! Threat model generated."
    echo ""
    echo "Summary:"
    grep -E "(title:|technical_assets:|trust_boundaries:)" threagile-generated.yaml
    echo ""
    echo "Full model saved to: threagile-generated.yaml"
else
    echo "❌ Failed to generate threat model"
    exit 1
fi

# Cleanup
rm -rf minimal-test