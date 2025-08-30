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

	// Merge all assets from parse results
	allAssets := []TechnicalAsset{}
	for _, result := range results {
		allAssets = append(allAssets, result.TechnicalAssets...)
		
		// Convert and add data assets
		for _, da := range result.DataAssets {
			model.DataAssets[da.ID] = &types.DataAsset{
				Id:    da.ID,
				Title: da.Title,
				Confidentiality: da.Classification,
				Quantity:        da.Quantity,
				Tags:            da.Tags,
			}
		}
	}

	// Detect trust boundaries if not explicitly provided
	boundaries := []TrustBoundary{}
	for _, result := range results {
		boundaries = append(boundaries, result.TrustBoundaries...)
	}
	if len(boundaries) == 0 && g.boundaryDetector != nil {
		boundaries = g.boundaryDetector.DetectBoundaries(allAssets)
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

	// Convert technical assets and assign to boundaries
	for _, asset := range allAssets {
		ta := &types.TechnicalAsset{
			Id:          asset.ID,
			Title:       asset.Title,
			Technologies: types.TechnologyList{mapTechnology(asset.Type)},
			Machine:     asset.Machine,
			Internet:    asset.Internet,
			Encryption:  asset.Encryption,
			Tags:        asset.Tags,
			CommunicationLinks: []*types.CommunicationLink{},
		}
		
		// Simple mode defaults
		ta.Size = types.Application
		ta.Type = types.Process
		ta.MultiTenant = false
		
		model.TechnicalAssets[asset.ID] = ta
		
		// Assign to boundary
		boundaryID := findBoundaryForAsset(asset, boundaries)
		if boundaryID != "" && model.TrustBoundaries[boundaryID] != nil {
			model.TrustBoundaries[boundaryID].TechnicalAssetsInside = 
				append(model.TrustBoundaries[boundaryID].TechnicalAssetsInside, asset.ID)
		}
	}

	// Convert communication links
	for _, result := range results {
		for _, comm := range result.Communications {
			link := types.CommunicationLink{
				Id:          comm.ID,
				Title:       comm.Title,
				TargetId:    comm.TargetID,
				Protocol:    comm.Protocol,
				Authentication: comm.Authentication,
				DataAssetsSent: comm.DataAssets,
			}
			
			// Add link to source asset
			if srcAsset, ok := model.TechnicalAssets[comm.SourceID]; ok {
				srcAsset.CommunicationLinks = append(srcAsset.CommunicationLinks, &link)
			}
		}
	}

	return model, nil
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

