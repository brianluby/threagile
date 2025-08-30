// +build integration

package ai_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/iac/kubernetes"
	"github.com/threagile/threagile/pkg/iac/terraform"
	"gopkg.in/yaml.v3"
)

func TestIntegration_TerraformToThreagile(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Create test Terraform file
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "main.tf")
	tfContent := `
resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_db_instance" "database" {
  engine = "postgres"
}

resource "aws_lb" "main" {
  name = "test-lb"
}
`
	err := os.WriteFile(tfFile, []byte(tfContent), 0644)
	require.NoError(t, err)

	// Create and configure orchestrator
	registry := ai.NewParserRegistry()
	err = terraform.RegisterParser(registry)
	require.NoError(t, err)

	orchestrator := ai.NewOrchestrator(registry)

	// Generate model
	options := ai.OrchestratorOptions{
		Directories: []string{tmpDir},
		Mode:        ai.GeneratorModeSimple,
	}

	model, err := orchestrator.GenerateModel(options)
	require.NoError(t, err)
	require.NotNil(t, model)

	// Verify generated model
	assert.Equal(t, "1.0.0", model.ThreagileVersion)
	assert.NotEmpty(t, model.Title)
	
	// Check assets were created
	assert.Len(t, model.TechnicalAssets, 4) // VPC, EC2, RDS, LB
	assert.Contains(t, model.TechnicalAssets, "vpc_test")
	assert.Contains(t, model.TechnicalAssets, "ec2_web")
	assert.Contains(t, model.TechnicalAssets, "rds_database")
	assert.Contains(t, model.TechnicalAssets, "lb_main")

	// Check trust boundaries
	assert.Greater(t, len(model.TrustBoundaries), 0)
	
	// Check communications were detected
	assert.Greater(t, len(model.CommunicationLinks), 0)

	// Verify model can be marshaled to YAML
	yamlData, err := yaml.Marshal(model)
	require.NoError(t, err)
	assert.NotEmpty(t, yamlData)
}

func TestIntegration_KubernetesToThreagile(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Create test Kubernetes manifest
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "app.yaml")
	k8sContent := `
apiVersion: v1
kind: Namespace
metadata:
  name: test-app
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: test-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
  namespace: test-app
spec:
  type: LoadBalancer
  selector:
    app: frontend
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: test-app
spec:
  rules:
  - host: app.example.com
`
	err := os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)

	// Create and configure orchestrator
	registry := ai.NewParserRegistry()
	err = kubernetes.RegisterParser(registry)
	require.NoError(t, err)

	orchestrator := ai.NewOrchestrator(registry)

	// Generate model
	options := ai.OrchestratorOptions{
		Directories: []string{tmpDir},
		Mode:        ai.GeneratorModeSimple,
	}

	model, err := orchestrator.GenerateModel(options)
	require.NoError(t, err)
	require.NotNil(t, model)

	// Verify generated model
	assert.Len(t, model.TechnicalAssets, 3) // Deployment, LoadBalancer, Ingress
	
	// Check namespace boundary was created
	var hasNamespaceBoundary bool
	for _, boundary := range model.TrustBoundaries {
		if boundary.Title == "Namespace: test-app" {
			hasNamespaceBoundary = true
			break
		}
	}
	assert.True(t, hasNamespaceBoundary, "Should have namespace trust boundary")

	// Verify assets are in the namespace
	for _, boundary := range model.TrustBoundaries {
		if boundary.Title == "Namespace: test-app" {
			assert.Greater(t, len(boundary.TechnicalAssetsInside), 0)
		}
	}
}

func TestIntegration_MixedInfrastructure(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Create test directories
	tmpDir := t.TempDir()
	tfDir := filepath.Join(tmpDir, "terraform")
	k8sDir := filepath.Join(tmpDir, "kubernetes")
	
	err := os.MkdirAll(tfDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(k8sDir, 0755)
	require.NoError(t, err)

	// Create Terraform file
	tfFile := filepath.Join(tfDir, "infra.tf")
	tfContent := `
resource "aws_rds_instance" "shared_db" {
  engine = "postgres"
}
`
	err = os.WriteFile(tfFile, []byte(tfContent), 0644)
	require.NoError(t, err)

	// Create Kubernetes file
	k8sFile := filepath.Join(k8sDir, "app.yaml")
	k8sContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  replicas: 3
`
	err = os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)

	// Create CLAUDE.md context file
	contextFile := filepath.Join(tmpDir, "CLAUDE.md")
	contextContent := `# Mixed Infrastructure Project
This project uses both AWS and Kubernetes.

## Security Requirements
- All data must be encrypted at rest
- HTTPS only for external communications
`
	err = os.WriteFile(contextFile, []byte(contextContent), 0644)
	require.NoError(t, err)

	// Create and configure orchestrator
	registry := ai.NewParserRegistry()
	err = terraform.RegisterParser(registry)
	require.NoError(t, err)
	err = kubernetes.RegisterParser(registry)
	require.NoError(t, err)

	orchestrator := ai.NewOrchestrator(registry)

	// Generate model with context
	options := ai.OrchestratorOptions{
		Directories:  []string{tfDir, k8sDir},
		Mode:         ai.GeneratorModeSimple,
		ContextFiles: []string{contextFile},
	}

	model, err := orchestrator.GenerateModel(options)
	require.NoError(t, err)
	require.NotNil(t, model)

	// Verify model includes both infrastructures
	assert.Equal(t, "Mixed Infrastructure Project Threat Model", model.Title)
	assert.Greater(t, len(model.TechnicalAssets), 1)
	
	// Check for both Terraform and K8s assets
	var hasTerraformAsset, hasK8sAsset bool
	for _, asset := range model.TechnicalAssets {
		for _, tag := range asset.Tags {
			if tag == "terraform" {
				hasTerraformAsset = true
			}
			if tag == "kubernetes" {
				hasK8sAsset = true
			}
		}
	}
	assert.True(t, hasTerraformAsset, "Should have Terraform assets")
	assert.True(t, hasK8sAsset, "Should have Kubernetes assets")

	// Check security requirements from context
	assert.Contains(t, model.SecurityRequirements, "All data must be encrypted at rest")
	assert.Contains(t, model.SecurityRequirements, "HTTPS only for external communications")
}