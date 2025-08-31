package ai

import (
	"fmt"
	"strings"
	"time"

	"github.com/threagile/threagile/pkg/types"
	"github.com/threagile/threagile/pkg/utils"
)

// SimpleGenerator implements Generator for simple mode
type SimpleGenerator struct {
	boundaryDetector TrustBoundaryDetector
}

// NewSimpleGenerator creates a new simple mode generator
func NewSimpleGenerator() *SimpleGenerator {
	return &SimpleGenerator{
		boundaryDetector: NewSimpleBoundaryDetector(),
	}
}

// Generate creates a minimal Threagile model focusing on trust boundaries
func (g *SimpleGenerator) Generate(results []*ParseResult, options GeneratorOptions) (*types.Model, error) {
	// Start with existing model or create new
	model := options.ExistingModel
	if model == nil {
		model = &types.Model{
			ThreagileVersion: "1.0.0",
			Title:            "Generated Threat Model",
			Date:             types.Date{Time: time.Now()},
			BusinessCriticality: types.Important,
			TechnicalAssets:  make(map[string]*types.TechnicalAsset),
			TrustBoundaries:  make(map[string]*types.TrustBoundary),
			DataAssets:       make(map[string]*types.DataAsset),
			CommunicationLinks: make(map[string]*types.CommunicationLink),
		}
	}

	// Convert IaC resources to technical assets
	for _, result := range results {
		// Convert generic resources
		for _, res := range result.Resources {
			asset := g.resourceToTechnicalAsset(res)
			model.TechnicalAssets[asset.Id] = asset
		}
		
		// Convert databases
		for _, db := range result.Databases {
			asset := g.databaseToTechnicalAsset(db)
			model.TechnicalAssets[asset.Id] = asset
			
			// Also create data asset for database
			dataAsset := g.createDataAsset(db)
			model.DataAssets[dataAsset.Id] = dataAsset
		}
		
		// Convert containers
		for _, container := range result.Containers {
			asset := g.containerToTechnicalAsset(container)
			model.TechnicalAssets[asset.Id] = asset
		}
		
		// Convert functions
		for _, fn := range result.Functions {
			asset := g.functionToTechnicalAsset(fn)
			model.TechnicalAssets[asset.Id] = asset
		}
		
		// Convert load balancers
		for _, lb := range result.LoadBalancers {
			asset := g.loadBalancerToTechnicalAsset(lb)
			model.TechnicalAssets[asset.Id] = asset
		}
	}

	// Detect trust boundaries using the boundary detector
	// First collect all technical assets for boundary detection
	technicalAssets := make([]TechnicalAsset, 0)
	for _, asset := range model.TechnicalAssets {
		technicalAssets = append(technicalAssets, TechnicalAsset{
			ID:    asset.Id,
			Title: asset.Title,
			Type:  AssetType(asset.Type.String()),
			Tags:  asset.Tags,
		})
	}
	
	boundaries := []TrustBoundary{}
	if g.boundaryDetector != nil && len(technicalAssets) > 0 {
		boundaries = g.boundaryDetector.DetectBoundaries(technicalAssets)
	}

	// Convert trust boundaries
	for _, tb := range boundaries {
		trustBoundary := &types.TrustBoundary{
			Id:          tb.ID,
			Title:       tb.Title,
			Description: tb.Description,
			Type:        mapBoundaryType(tb.Type),
			Tags:        tb.Tags,
			TechnicalAssetsInside: []string{},
		}
		model.TrustBoundaries[tb.ID] = trustBoundary
	}

	// Assign technical assets to trust boundaries
	for _, ta := range model.TechnicalAssets {
		// Find appropriate boundary for this asset
		for _, tb := range model.TrustBoundaries {
			// Simple assignment: put all assets in the first trust boundary
			// In detailed mode, this would be more sophisticated
			tb.TechnicalAssetsInside = append(tb.TechnicalAssetsInside, ta.Id)
			break
		}
	}

	// In simple mode, we don't generate communication links
	// Those would be added in detailed mode or by the user

	return model, nil
}

// Helper conversion methods
func (g *SimpleGenerator) resourceToTechnicalAsset(res *Resource) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:    res.ID,
		Title: res.Name,
		Type:  types.Process,
		Size:  types.Application,
		Technologies: types.TechnologyList{
			mapResourceTypeToTechnology(res.Type),
		},
		Tags: convertTags(res.Tags),
		CommunicationLinks: []*types.CommunicationLink{},
	}
}

func (g *SimpleGenerator) databaseToTechnicalAsset(db *Database) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:    db.ID,
		Title: db.Name,
		Type:  types.Datastore,
		Size:  types.System,
		Technologies: types.TechnologyList{
			mapDatabaseTypeToTechnology(db.Type),
		},
		Encryption: types.Transparent,
		Tags: convertTags(db.Tags),
		CommunicationLinks: []*types.CommunicationLink{},
	}
}

func (g *SimpleGenerator) containerToTechnicalAsset(container *Container) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:    container.ID,
		Title: container.Name,
		Type:  types.Process,
		Size:  types.Service,
		Machine: types.Container,
		Technologies: types.TechnologyList{
			&types.Technology{Name: "docker"},
		},
		Tags: convertTags(container.Tags),
		CommunicationLinks: []*types.CommunicationLink{},
	}
}

func (g *SimpleGenerator) functionToTechnicalAsset(fn *Function) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:    fn.ID,
		Title: fn.Name,
		Type:  types.Process,
		Size:  types.Service,
		Machine: types.Serverless,
		Technologies: types.TechnologyList{
			mapFunctionRuntimeToTechnology(fn.Runtime),
		},
		Tags: convertTags(fn.Tags),
		CommunicationLinks: []*types.CommunicationLink{},
	}
}

func (g *SimpleGenerator) loadBalancerToTechnicalAsset(lb *LoadBalancer) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:    lb.ID,
		Title: lb.Name,
		Type:  types.Process,
		Size:  types.Component,
		Technologies: types.TechnologyList{
			&types.Technology{Name: "load-balancer"},
		},
		Internet: lb.Type == "internet-facing",
		Tags: convertTags(lb.Tags),
		CommunicationLinks: []*types.CommunicationLink{},
	}
}

func (g *SimpleGenerator) createDataAsset(db *Database) *types.DataAsset {
	return &types.DataAsset{
		Id:    fmt.Sprintf("data-%s", db.ID),
		Title: fmt.Sprintf("%s Data", db.Name),
		Description: fmt.Sprintf("Data stored in %s database", db.Name),
		Usage: types.Business,
		Tags: convertTags(db.Tags),
		Origin: "IaC",
		Owner: "system",
		Quantity: types.Many,
		Confidentiality: types.Confidential,
		Integrity: types.Critical,
		Availability: types.Critical,
	}
}

// SimpleBoundaryDetector implements basic trust boundary detection
type SimpleBoundaryDetector struct{}

// NewSimpleBoundaryDetector creates a new boundary detector
func NewSimpleBoundaryDetector() *SimpleBoundaryDetector {
	return &SimpleBoundaryDetector{}
}

// DetectBoundaries suggests trust boundaries based on asset properties
func (d *SimpleBoundaryDetector) DetectBoundaries(assets []TechnicalAsset) []TrustBoundary {
	boundaries := []TrustBoundary{}
	boundaryMap := make(map[string][]string) // boundary key -> asset IDs
	
	for _, asset := range assets {
		// Group by network properties
		boundaryKey := detectBoundaryKey(asset)
		boundaryMap[boundaryKey] = append(boundaryMap[boundaryKey], asset.ID)
	}
	
	// Create boundaries from groups
	for key, assetIDs := range boundaryMap {
		if len(assetIDs) > 0 {
			boundary := TrustBoundary{
				ID:     utils.SanitizeID(key),
				Title:  generateBoundaryTitle(key),
				Type:   detectBoundaryType(key),
				Assets: assetIDs,
			}
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// Helper functions

func mapBoundaryType(bt BoundaryType) types.TrustBoundaryType {
	switch bt {
	case BoundaryTypeNetwork:
		return types.NetworkOnPrem
	case BoundaryTypeCloudAccount:
		return types.NetworkCloudProvider
	case BoundaryTypeK8sNamespace:
		return types.NetworkCloudProvider
	case BoundaryTypeVPC:
		return types.NetworkVirtualLAN
	default:
		return types.NetworkOnPrem
	}
}

func mapTechnology(at AssetType) *types.Technology {
	var techName string
	switch at {
	case AssetTypeCompute:
		techName = types.UnknownTechnology
	case AssetTypeStorage:
		techName = types.FileServer
	case AssetTypeDatabase:
		techName = types.Database
	case AssetTypeContainer:
		techName = types.ContainerPlatform
	case AssetTypeServerless:
		techName = types.Task
	case AssetTypeLoadBalancer:
		techName = types.LoadBalancer
	default:
		techName = types.UnknownTechnology
	}
	return &types.Technology{Name: techName}
}

func findBoundaryForAsset(asset TechnicalAsset, boundaries []TrustBoundary) string {
	for _, boundary := range boundaries {
		for _, id := range boundary.Assets {
			if id == asset.ID {
				return boundary.ID
			}
		}
	}
	return ""
}

// Additional helper functions
func convertTags(tags map[string]string) []string {
	result := make([]string, 0, len(tags))
	for k, v := range tags {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
	}
	return result
}

func mapResourceTypeToTechnology(resourceType string) *types.Technology {
	// Map common resource types to technologies
	switch strings.ToLower(resourceType) {
	case "aws_instance", "ec2":
		return &types.Technology{Name: types.UnknownTechnology}
	case "aws_lambda":
		return &types.Technology{Name: types.UnknownTechnology}
	default:
		return &types.Technology{Name: types.UnknownTechnology}
	}
}

func mapDatabaseTypeToTechnology(dbType string) *types.Technology {
	switch strings.ToLower(dbType) {
	case "mysql":
		return &types.Technology{Name: "mysql"}
	case "postgres", "postgresql":
		return &types.Technology{Name: "postgresql"}
	case "dynamodb":
		return &types.Technology{Name: types.UnknownTechnology} // Would need to add DynamoDB
	case "mongodb":
		return &types.Technology{Name: "mongodb"}
	default:
		return &types.Technology{Name: types.UnknownTechnology}
	}
}

func mapFunctionRuntimeToTechnology(runtime string) *types.Technology {
	switch {
	case strings.Contains(runtime, "python"):
		return &types.Technology{Name: types.UnknownTechnology} // Would need Python technology
	case strings.Contains(runtime, "node"):
		return &types.Technology{Name: "nodejs"}
	case strings.Contains(runtime, "java"):
		return &types.Technology{Name: types.UnknownTechnology} // Would need Java technology
	case strings.Contains(runtime, "go"):
		return &types.Technology{Name: types.UnknownTechnology} // Would need Go technology
	default:
		return &types.Technology{Name: types.UnknownTechnology}
	}
}

func detectBoundaryKey(asset TechnicalAsset) string {
	// Extract boundary hints from properties
	if vpc, ok := asset.Properties["vpc"].(string); ok {
		return "vpc-" + vpc
	}
	if namespace, ok := asset.Properties["namespace"].(string); ok {
		return "k8s-" + namespace
	}
	if subnet, ok := asset.Properties["subnet"].(string); ok {
		return "subnet-" + subnet
	}
	if env, ok := asset.Properties["environment"].(string); ok {
		return "env-" + env
	}
	
	// Default boundary
	return "default-boundary"
}

func detectBoundaryType(key string) BoundaryType {
	if strings.HasPrefix(key, "vpc-") {
		return BoundaryTypeVPC
	}
	if strings.HasPrefix(key, "k8s-") {
		return BoundaryTypeK8sNamespace
	}
	if strings.HasPrefix(key, "subnet-") {
		return BoundaryTypeSubnet
	}
	if strings.HasPrefix(key, "env-") {
		return BoundaryTypeEnvironment
	}
	return BoundaryTypeNetwork
}

func generateBoundaryTitle(key string) string {
	parts := strings.Split(key, "-")
	if len(parts) >= 2 {
		boundaryType := parts[0]
		name := strings.Join(parts[1:], "-")
		return fmt.Sprintf("%s %s", strings.Title(boundaryType), name)
	}
	return "Default Network"
}

