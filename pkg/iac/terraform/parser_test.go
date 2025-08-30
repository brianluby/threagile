package terraform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/ai"
)

func TestParser_Name(t *testing.T) {
	p := NewParser()
	assert.Equal(t, "terraform", p.Name())
}

func TestParser_SupportedExtensions(t *testing.T) {
	p := NewParser()
	exts := p.SupportedExtensions()
	assert.Contains(t, exts, ".tf")
	assert.Contains(t, exts, ".tf.json")
	assert.Contains(t, exts, ".tfvars")
	assert.Contains(t, exts, ".tfvars.json")
}

func TestParser_Parse_SimpleVPC(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "main.tf")
	
	tfContent := `
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_db_instance" "database" {
  allocated_storage = 20
  engine           = "postgres"
}

resource "aws_s3_bucket" "storage" {
  bucket = "my-bucket"
}
`
	
	err := os.WriteFile(tfFile, []byte(tfContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{tfFile})
	require.NoError(t, err)
	require.NotNil(t, result)
	
	// Verify assets were extracted
	assert.Len(t, result.TechnicalAssets, 4)
	assert.Len(t, result.TrustBoundaries, 2) // VPC + default
	assert.Len(t, result.DataAssets, 2)      // RDS + S3
	
	// Check specific assets
	var hasVPC, hasEC2, hasRDS, hasS3 bool
	for _, asset := range result.TechnicalAssets {
		switch asset.Type {
		case ai.AssetTypeNetwork:
			hasVPC = true
			assert.Equal(t, "vpc_main", asset.ID)
		case ai.AssetTypeCompute:
			hasEC2 = true
			assert.Equal(t, "ec2_web", asset.ID)
		case ai.AssetTypeDatabase:
			hasRDS = true
			assert.Equal(t, "rds_database", asset.ID)
		case ai.AssetTypeStorage:
			hasS3 = true
			assert.Equal(t, "s3_storage", asset.ID)
		}
	}
	
	assert.True(t, hasVPC, "Should have VPC asset")
	assert.True(t, hasEC2, "Should have EC2 asset")
	assert.True(t, hasRDS, "Should have RDS asset")
	assert.True(t, hasS3, "Should have S3 asset")
	
	// Check communications were detected
	assert.Greater(t, len(result.Communications), 0, "Should have detected communications")
}

func TestParser_Parse_LoadBalancer(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "alb.tf")
	
	tfContent := `
resource "aws_lb" "main" {
  name               = "main-lb"
  load_balancer_type = "application"
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
`
	
	err := os.WriteFile(tfFile, []byte(tfContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{tfFile})
	require.NoError(t, err)
	
	// Check that communication was detected between LB and EC2
	var hasLBToEC2Comm bool
	for _, comm := range result.Communications {
		if comm.SourceID == "lb_main" && comm.TargetID == "ec2_app" {
			hasLBToEC2Comm = true
			assert.Equal(t, "HTTP Traffic", comm.Title)
		}
	}
	assert.True(t, hasLBToEC2Comm, "Should have LB to EC2 communication")
}

func TestParser_Parse_Lambda(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "lambda.tf")
	
	tfContent := `
resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  runtime      = "nodejs14.x"
}

resource "aws_s3_bucket" "data" {
  bucket = "data-bucket"
}
`
	
	err := os.WriteFile(tfFile, []byte(tfContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{tfFile})
	require.NoError(t, err)
	
	// Check Lambda was extracted
	var hasLambda bool
	for _, asset := range result.TechnicalAssets {
		if asset.Type == ai.AssetTypeServerless {
			hasLambda = true
			assert.Equal(t, "lambda_processor", asset.ID)
		}
	}
	assert.True(t, hasLambda, "Should have Lambda asset")
	
	// Check Lambda to S3 communication
	var hasLambdaToS3Comm bool
	for _, comm := range result.Communications {
		if comm.SourceID == "lambda_processor" && comm.TargetID == "s3_data" {
			hasLambdaToS3Comm = true
			assert.Equal(t, "S3 Access", comm.Title)
		}
	}
	assert.True(t, hasLambdaToS3Comm, "Should have Lambda to S3 communication")
}