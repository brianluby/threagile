package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/types"
)

func TestParser_Name(t *testing.T) {
	p := NewParser()
	assert.Equal(t, "kubernetes", p.Name())
}

func TestParser_SupportedExtensions(t *testing.T) {
	p := NewParser()
	exts := p.SupportedExtensions()
	assert.Contains(t, exts, ".yaml")
	assert.Contains(t, exts, ".yml")
}

func TestParser_Parse_SimpleDeployment(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "deployment.yaml")
	
	k8sContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
---
apiVersion: v1
kind: Service
metadata:
  name: web-service
  namespace: production
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 80
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-storage
  namespace: production
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
`
	
	err := os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{k8sFile})
	require.NoError(t, err)
	require.NotNil(t, result)
	
	// Verify assets were extracted
	assert.Len(t, result.TechnicalAssets, 3) // Deployment, LoadBalancer Service, PVC
	assert.Len(t, result.TrustBoundaries, 1) // production namespace
	assert.Len(t, result.DataAssets, 1)      // PVC data
	
	// Check specific assets
	var hasDeployment, hasLB, hasPVC bool
	for _, asset := range result.TechnicalAssets {
		switch asset.ID {
		case "k8s_deployment_web_app":
			hasDeployment = true
			assert.Equal(t, ai.AssetTypeContainer, asset.Type)
			assert.Equal(t, "production", asset.Properties["namespace"])
		case "k8s_svc_lb_web_service":
			hasLB = true
			assert.Equal(t, ai.AssetTypeLoadBalancer, asset.Type)
		case "k8s_pvc_data_storage":
			hasPVC = true
			assert.Equal(t, ai.AssetTypeStorage, asset.Type)
		}
	}
	
	assert.True(t, hasDeployment, "Should have Deployment asset")
	assert.True(t, hasLB, "Should have LoadBalancer asset")
	assert.True(t, hasPVC, "Should have PVC asset")
	
	// Check namespace boundary
	assert.Equal(t, "k8s_ns_production", result.TrustBoundaries[0].ID)
	assert.Equal(t, "Namespace: production", result.TrustBoundaries[0].Title)
	assert.Len(t, result.TrustBoundaries[0].Assets, 3)
	
	// Check communications were detected
	assert.Greater(t, len(result.Communications), 0, "Should have detected communications")
}

func TestParser_Parse_Ingress(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "ingress.yaml")
	
	k8sContent := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: api
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-backend
  namespace: api
spec:
  replicas: 2
`
	
	err := os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{k8sFile})
	require.NoError(t, err)
	
	// Check Ingress was extracted
	var hasIngress bool
	for _, asset := range result.TechnicalAssets {
		if asset.ID == "k8s_ingress_api_ingress" {
			hasIngress = true
			assert.Equal(t, ai.AssetTypeLoadBalancer, asset.Type)
			assert.True(t, asset.Internet)
		}
	}
	assert.True(t, hasIngress, "Should have Ingress asset")
	
	// Check communication from Ingress to backend
	var hasIngressComm bool
	for _, comm := range result.Communications {
		if comm.SourceID == "k8s_ingress_api_ingress" {
			hasIngressComm = true
		}
	}
	assert.True(t, hasIngressComm, "Should have Ingress communication")
}

func TestParser_Parse_MultipleNamespaces(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "multi-ns.yaml")
	
	k8sContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: frontend
spec:
  replicas: 2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: backend
spec:
  replicas: 3
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
  namespace: data
spec:
  replicas: 1
`
	
	err := os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{k8sFile})
	require.NoError(t, err)
	
	// Should have 3 namespace boundaries
	assert.Len(t, result.TrustBoundaries, 3)
	
	// Check namespaces
	namespaces := make(map[string]bool)
	for _, boundary := range result.TrustBoundaries {
		if ns, ok := boundary.Properties["namespace"].(string); ok {
			namespaces[ns] = true
		}
	}
	assert.True(t, namespaces["frontend"])
	assert.True(t, namespaces["backend"])
	assert.True(t, namespaces["data"])
}

func TestParser_Parse_Secrets(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	k8sFile := filepath.Join(tmpDir, "secrets.yaml")
	
	k8sContent := `
apiVersion: v1
kind: Secret
metadata:
  name: api-keys
  namespace: default
type: Opaque
data:
  api-key: YXBpLWtleS12YWx1ZQ==
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  config.yaml: |
    debug: false
    port: 8080
`
	
	err := os.WriteFile(k8sFile, []byte(k8sContent), 0644)
	require.NoError(t, err)
	
	// Parse the file
	p := NewParser()
	result, err := p.Parse([]string{k8sFile})
	require.NoError(t, err)
	
	// Should have data assets for secret and configmap
	assert.Len(t, result.DataAssets, 2)
	
	// Check secret has higher classification
	for _, da := range result.DataAssets {
		if da.ID == "data_secret_api_keys" {
			assert.Equal(t, types.StrictlyConfidential, da.Classification)
		}
		if da.ID == "data_configmap_app_config" {
			assert.Equal(t, types.Confidential, da.Classification)
		}
	}
}