package kubernetes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/types"
	"github.com/threagile/threagile/pkg/utils"
	"gopkg.in/yaml.v3"
)

// Parser implements the ai.Parser interface for Kubernetes manifests
type Parser struct{}

// NewParser creates a new Kubernetes parser
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the parser name
func (p *Parser) Name() string {
	return "kubernetes"
}

// SupportedExtensions returns file extensions this parser handles
func (p *Parser) SupportedExtensions() []string {
	return []string{".yaml", ".yml"}
}

// Parse analyzes Kubernetes manifest files and extracts infrastructure components
func (p *Parser) Parse(files []string) (*ai.ParseResult, error) {
	result := &ai.ParseResult{
		TechnicalAssets: []ai.TechnicalAsset{},
		TrustBoundaries: []ai.TrustBoundary{},
		Communications:  []ai.CommunicationLink{},
		DataAssets:      []ai.DataAsset{},
		Metadata: map[string]interface{}{
			"parser": "kubernetes",
			"files":  len(files),
		},
	}

	// Track namespaces and services for communication detection
	namespaces := make(map[string]bool)
	services := make(map[string]serviceInfo)
	deployments := make(map[string]deploymentInfo)
	
	// Parse each file
	for _, file := range files {
		// Skip non-K8s YAML files
		if !p.isKubernetesFile(file) {
			continue
		}
		
		manifests, err := p.parseManifestFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
		
		for _, manifest := range manifests {
			if err := p.processManifest(manifest, file, result, namespaces, services, deployments); err != nil {
				return nil, fmt.Errorf("failed to process manifest in %s: %w", file, err)
			}
		}
	}

	// Create trust boundaries from namespaces
	for ns := range namespaces {
		if ns != "" && ns != "default" {
			boundary := ai.TrustBoundary{
				ID:    "k8s_ns_" + utils.SanitizeID(ns),
				Title: "Namespace: " + ns,
				Type:  ai.BoundaryTypeK8sNamespace,
				Properties: map[string]interface{}{
					"namespace": ns,
				},
			}
			result.TrustBoundaries = append(result.TrustBoundaries, boundary)
		}
	}
	
	// Assign assets to namespace boundaries
	p.assignAssetsToBoundaries(result)
	
	// Detect communications based on services
	p.detectServiceCommunications(result, services, deployments)

	return result, nil
}

// isKubernetesFile checks if a YAML file contains K8s resources
func (p *Parser) isKubernetesFile(filePath string) bool {
	// Simple heuristic: check if file contains apiVersion
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "apiVersion:")
}

// parseManifestFile parses a YAML file that may contain multiple documents
func (p *Parser) parseManifestFile(filePath string) ([]manifest, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var manifests []manifest
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	
	for {
		var m manifest
		err := decoder.Decode(&m)
		if err != nil {
			break // End of documents
		}
		if m.APIVersion != "" && m.Kind != "" {
			manifests = append(manifests, m)
		}
	}

	return manifests, nil
}

// processManifest converts a K8s manifest to Threagile assets
func (p *Parser) processManifest(m manifest, sourceFile string, result *ai.ParseResult, 
	namespaces map[string]bool, services map[string]serviceInfo, deployments map[string]deploymentInfo) error {
	
	namespace := m.Metadata.Namespace
	if namespace == "" {
		namespace = "default"
	}
	namespaces[namespace] = true

	switch m.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		asset := p.workloadToAsset(m, sourceFile)
		result.TechnicalAssets = append(result.TechnicalAssets, asset)
		
		// Track deployment info
		deployments[asset.ID] = deploymentInfo{
			Name:      m.Metadata.Name,
			Namespace: namespace,
			Labels:    m.Metadata.Labels,
		}
		
	case "Service":
		// Services create communication endpoints
		svc := serviceInfo{
			Name:      m.Metadata.Name,
			Namespace: namespace,
			Selector:  extractSelector(m),
			Type:      extractServiceType(m),
		}
		services[fmt.Sprintf("%s/%s", namespace, m.Metadata.Name)] = svc
		
		// Create asset for LoadBalancer services
		if svc.Type == "LoadBalancer" {
			asset := p.serviceToAsset(m, sourceFile)
			result.TechnicalAssets = append(result.TechnicalAssets, asset)
		}
		
	case "Ingress":
		asset := p.ingressToAsset(m, sourceFile)
		result.TechnicalAssets = append(result.TechnicalAssets, asset)
		
	case "PersistentVolumeClaim":
		asset := p.pvcToAsset(m, sourceFile)
		result.TechnicalAssets = append(result.TechnicalAssets, asset)
		
		// Add data asset for storage
		dataAsset := ai.DataAsset{
			ID:    "data_pvc_" + utils.SanitizeID(m.Metadata.Name),
			Title: "PVC Data: " + m.Metadata.Name,
			Classification: types.Confidential,
			Quantity: types.Many,
		}
		result.DataAssets = append(result.DataAssets, dataAsset)
		
	case "ConfigMap", "Secret":
		// These often contain configuration data
		dataAsset := ai.DataAsset{
			ID:    fmt.Sprintf("data_%s_%s", strings.ToLower(m.Kind), utils.SanitizeID(m.Metadata.Name)),
			Title: fmt.Sprintf("%s: %s", m.Kind, m.Metadata.Name),
			Classification: types.Confidential,
			Quantity: types.Few,
			Tags: []string{"kubernetes", strings.ToLower(m.Kind)},
		}
		if m.Kind == "Secret" {
			dataAsset.Classification = types.StrictlyConfidential
		}
		result.DataAssets = append(result.DataAssets, dataAsset)
		
	case "Namespace":
		// Already tracked in namespaces map
	}

	return nil
}

// Asset conversion functions

func (p *Parser) workloadToAsset(m manifest, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:    fmt.Sprintf("k8s_%s_%s", strings.ToLower(m.Kind), utils.SanitizeID(m.Metadata.Name)),
		Title: fmt.Sprintf("%s: %s", m.Kind, m.Metadata.Name),
		Type:  ai.AssetTypeContainer,
		Technology: types.Technology{Name: types.ContainerPlatform},
		Machine:    types.Container,
		Internet:   false,
		Encryption: types.NoneEncryption,
		Tags:       []string{"kubernetes", strings.ToLower(m.Kind), m.Metadata.Namespace},
		IACSource:  filepath.Base(sourceFile),
		Properties: map[string]interface{}{
			"namespace": m.Metadata.Namespace,
			"kind":      m.Kind,
			"labels":    m.Metadata.Labels,
		},
	}
}

func (p *Parser) serviceToAsset(m manifest, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:    "k8s_svc_lb_" + utils.SanitizeID(m.Metadata.Name),
		Title: "LoadBalancer: " + m.Metadata.Name,
		Type:  ai.AssetTypeLoadBalancer,
		Technology: types.Technology{Name: types.LoadBalancer},
		Machine:    types.Virtual,
		Internet:   true, // LoadBalancer services are typically internet-facing
		Encryption: types.DataWithAsymmetricSharedKey,
		Tags:       []string{"kubernetes", "service", "loadbalancer", m.Metadata.Namespace},
		IACSource:  filepath.Base(sourceFile),
		Properties: map[string]interface{}{
			"namespace": m.Metadata.Namespace,
			"type":      "LoadBalancer",
		},
	}
}

func (p *Parser) ingressToAsset(m manifest, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:    "k8s_ingress_" + utils.SanitizeID(m.Metadata.Name),
		Title: "Ingress: " + m.Metadata.Name,
		Type:  ai.AssetTypeLoadBalancer,
		Technology: types.Technology{Name: types.ReverseProxy},
		Machine:    types.Virtual,
		Internet:   true,
		Encryption: types.DataWithAsymmetricSharedKey,
		Tags:       []string{"kubernetes", "ingress", m.Metadata.Namespace},
		IACSource:  filepath.Base(sourceFile),
		Properties: map[string]interface{}{
			"namespace": m.Metadata.Namespace,
		},
	}
}

func (p *Parser) pvcToAsset(m manifest, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:    "k8s_pvc_" + utils.SanitizeID(m.Metadata.Name),
		Title: "Storage: " + m.Metadata.Name,
		Type:  ai.AssetTypeStorage,
		Technology: types.Technology{Name: types.FileServer},
		Machine:    types.Virtual,
		Internet:   false,
		Encryption: types.DataWithSymmetricSharedKey,
		Tags:       []string{"kubernetes", "storage", "pvc", m.Metadata.Namespace},
		IACSource:  filepath.Base(sourceFile),
		Properties: map[string]interface{}{
			"namespace": m.Metadata.Namespace,
		},
	}
}

// assignAssetsToBoundaries assigns assets to their namespace boundaries
func (p *Parser) assignAssetsToBoundaries(result *ai.ParseResult) {
	for i := range result.TrustBoundaries {
		boundary := &result.TrustBoundaries[i]
		if ns, ok := boundary.Properties["namespace"].(string); ok {
			boundary.Assets = []string{}
			for _, asset := range result.TechnicalAssets {
				if assetNs, ok := asset.Properties["namespace"].(string); ok && assetNs == ns {
					boundary.Assets = append(boundary.Assets, asset.ID)
				}
			}
		}
	}
	
	// Create default boundary for assets without namespace
	unboundedAssets := []string{}
	for _, asset := range result.TechnicalAssets {
		bounded := false
		for _, boundary := range result.TrustBoundaries {
			for _, id := range boundary.Assets {
				if id == asset.ID {
					bounded = true
					break
				}
			}
		}
		if !bounded {
			unboundedAssets = append(unboundedAssets, asset.ID)
		}
	}
	
	if len(unboundedAssets) > 0 {
		defaultBoundary := ai.TrustBoundary{
			ID:    "k8s_default",
			Title: "Default Kubernetes Network",
			Type:  ai.BoundaryTypeK8sNamespace,
			Assets: unboundedAssets,
		}
		result.TrustBoundaries = append(result.TrustBoundaries, defaultBoundary)
	}
}

// detectServiceCommunications creates communication links based on services
func (p *Parser) detectServiceCommunications(result *ai.ParseResult, services map[string]serviceInfo, deployments map[string]deploymentInfo) {
	// Ingress/LoadBalancer to backend services
	for _, asset := range result.TechnicalAssets {
		if asset.Type == ai.AssetTypeLoadBalancer {
			ns := asset.Properties["namespace"].(string)
			// Connect to deployments in same namespace
			for depID, depInfo := range deployments {
				if depInfo.Namespace == ns {
					comm := ai.CommunicationLink{
						ID:       fmt.Sprintf("comm_%s_to_%s", asset.ID, depID),
						SourceID: asset.ID,
						TargetID: depID,
						Title:    "HTTP/HTTPS Traffic",
						Protocol: types.HTTPS,
						Encryption: types.DataWithAsymmetricSharedKey,
						Authentication: types.NoneAuthentication,
					}
					result.Communications = append(result.Communications, comm)
				}
			}
		}
	}
	
	// Service mesh communications (simplified for MVP)
	// Connect deployments that might communicate
	for id1, dep1 := range deployments {
		for id2, dep2 := range deployments {
			if id1 != id2 && dep1.Namespace == dep2.Namespace {
				comm := ai.CommunicationLink{
					ID:       fmt.Sprintf("comm_%s_to_%s", id1, id2),
					SourceID: id1,
					TargetID: id2,
					Title:    "Service Mesh",
					Protocol: types.HTTP,
					Encryption: types.NoneEncryption,
					Authentication: types.NoneAuthentication,
				}
				result.Communications = append(result.Communications, comm)
			}
		}
	}
}

// Helper types and functions

type manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace"`
		Labels    map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec   map[string]interface{} `yaml:"spec"`
	Status map[string]interface{} `yaml:"status"`
}

type serviceInfo struct {
	Name      string
	Namespace string
	Type      string
	Selector  map[string]string
}

type deploymentInfo struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

func extractSelector(m manifest) map[string]string {
	if spec, ok := m.Spec["selector"].(map[string]interface{}); ok {
		selector := make(map[string]string)
		for k, v := range spec {
			if str, ok := v.(string); ok {
				selector[k] = str
			}
		}
		return selector
	}
	return nil
}

func extractServiceType(m manifest) string {
	if svcType, ok := m.Spec["type"].(string); ok {
		return svcType
	}
	return "ClusterIP"
}


// RegisterParser registers the Kubernetes parser with the AI registry
func RegisterParser(registry ai.ParserRegistry) error {
	return registry.Register(NewParser())
}