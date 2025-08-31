package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func TestTrustBoundaryDetector_DetectBoundaries(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	tests := []struct {
		name    string
		model   *types.Model
		results []*ParseResult
		check   func(t *testing.T, boundaries []*types.TrustBoundary)
	}{
		{
			name: "Network-based boundaries",
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"web-server": {
						Id:    "web-server",
						Title: "Web Server",
						Type:  "process",
						Tags:  []string{"provider:aws", "zone:public"},
					},
					"api-server": {
						Id:    "api-server",
						Title: "API Server",
						Type:  "process",
						Tags:  []string{"provider:aws", "zone:private"},
					},
				},
				CommunicationLinks: map[string]*types.CommunicationLink{},
			},
			results: []*ParseResult{
				{
					Networks: map[string]*Network{
						"vpc-main": {
							ID:       "vpc-main",
							Name:     "Main VPC",
							Type:     "vpc",
							Provider: "aws",
						},
						"subnet-public": {
							ID:       "subnet-public",
							Name:     "Public Subnet",
							Type:     "subnet",
							Provider: "aws",
						},
						"subnet-private": {
							ID:       "subnet-private",
							Name:     "Private Subnet",
							Type:     "subnet",
							Provider: "aws",
						},
					},
				},
			},
			check: func(t *testing.T, boundaries []*types.TrustBoundary) {
				assert.NotEmpty(t, boundaries)
				
				// Check for VPC boundary
				hasVPCBoundary := false
				for _, b := range boundaries {
					if b.Type == "network-cloud-provider" && contains(b.Tags, "type:vpc") {
						hasVPCBoundary = true
						break
					}
				}
				assert.True(t, hasVPCBoundary, "Should detect VPC boundary")
			},
		},
		{
			name: "Security zone boundaries",
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"public-web": {
						Id:    "public-web",
						Title: "Public Web Server",
						Type:  "external-entity",
						Tags:  []string{},
					},
					"internal-api": {
						Id:    "internal-api",
						Title: "Internal API",
						Type:  "process",
						Tags:  []string{"zone:private"},
					},
					"sensitive-db": {
						Id:    "sensitive-db",
						Title: "Sensitive Database",
						Type:  "datastore",
						Tags:  []string{"restricted", "encrypted"},
					},
				},
				CommunicationLinks: map[string]*types.CommunicationLink{},
			},
			results: []*ParseResult{},
			check: func(t *testing.T, boundaries []*types.TrustBoundary) {
				assert.NotEmpty(t, boundaries)
				
				// Check for different security zones
				hasPublicZone := false
				hasPrivateZone := false
				hasRestrictedZone := false
				
				for _, b := range boundaries {
					for _, tag := range b.Tags {
						if tag == "zone:public" {
							hasPublicZone = true
						}
						if tag == "zone:private" {
							hasPrivateZone = true
						}
						if tag == "zone:restricted" {
							hasRestrictedZone = true
						}
					}
				}
				
				assert.True(t, hasPublicZone, "Should detect public zone")
				assert.True(t, hasPrivateZone, "Should detect private zone")
				assert.True(t, hasRestrictedZone, "Should detect restricted zone")
			},
		},
		{
			name: "Provider boundaries",
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"aws-resource": {
						Id:    "aws-resource",
						Title: "AWS Resource",
						Type:  "process",
						Tags:  []string{"provider:aws"},
					},
					"gcp-resource": {
						Id:    "gcp-resource",
						Title: "GCP Resource",
						Type:  "process",
						Tags:  []string{"provider:gcp"},
					},
					"azure-resource": {
						Id:    "azure-resource",
						Title: "Azure Resource",
						Type:  "process",
						Tags:  []string{"provider:azure"},
					},
				},
				CommunicationLinks: map[string]*types.CommunicationLink{},
			},
			results: []*ParseResult{
				{
					Resources: map[string]*Resource{
						"aws-resource": {
							ID:       "aws-resource",
							Name:     "AWS Resource",
							Provider: "aws",
						},
						"gcp-resource": {
							ID:       "gcp-resource",
							Name:     "GCP Resource",
							Provider: "gcp",
						},
						"azure-resource": {
							ID:       "azure-resource",
							Name:     "Azure Resource",
							Provider: "azure",
						},
					},
				},
			},
			check: func(t *testing.T, boundaries []*types.TrustBoundary) {
				assert.NotEmpty(t, boundaries)
				
				// Check for provider boundaries
				hasAWSBoundary := false
				hasGCPBoundary := false
				hasAzureBoundary := false
				
				for _, b := range boundaries {
					if contains(b.Tags, "provider:aws") {
						hasAWSBoundary = true
					}
					if contains(b.Tags, "provider:gcp") {
						hasGCPBoundary = true
					}
					if contains(b.Tags, "provider:azure") {
						hasAzureBoundary = true
					}
				}
				
				assert.True(t, hasAWSBoundary, "Should detect AWS boundary")
				assert.True(t, hasGCPBoundary, "Should detect GCP boundary")
				assert.True(t, hasAzureBoundary, "Should detect Azure boundary")
			},
		},
		{
			name: "Compliance boundaries",
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"payment-processor": {
						Id:    "payment-processor",
						Title: "Payment Processor",
						Type:  "process",
						Tags:  []string{"compliance:pci-dss"},
					},
					"patient-records": {
						Id:    "patient-records",
						Title: "Patient Records",
						Type:  "datastore",
						Tags:  []string{"compliance:hipaa"},
					},
					"user-data": {
						Id:    "user-data",
						Title: "User Data",
						Type:  "datastore",
						Tags:  []string{"compliance:gdpr"},
					},
				},
				DataAssets: map[string]*types.DataAsset{
					"payment-data": {
						Id:              "payment-data",
						Title:           "Payment Data",
						Confidentiality: "strictly-confidential",
					},
				},
				CommunicationLinks: map[string]*types.CommunicationLink{},
			},
			results: []*ParseResult{},
			check: func(t *testing.T, boundaries []*types.TrustBoundary) {
				assert.NotEmpty(t, boundaries)
				
				// Check for compliance boundaries
				hasPCIBoundary := false
				hasHIPAABoundary := false
				hasGDPRBoundary := false
				
				for _, b := range boundaries {
					if contains(b.Tags, "compliance:pci-dss") {
						hasPCIBoundary = true
					}
					if contains(b.Tags, "compliance:hipaa") {
						hasHIPAABoundary = true
					}
					if contains(b.Tags, "compliance:gdpr") {
						hasGDPRBoundary = true
					}
				}
				
				assert.True(t, hasPCIBoundary, "Should detect PCI boundary")
				assert.True(t, hasHIPAABoundary, "Should detect HIPAA boundary")
				assert.True(t, hasGDPRBoundary, "Should detect GDPR boundary")
			},
		},
		{
			name: "Data flow boundaries",
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"service-a": {
						Id:    "service-a",
						Title: "Service A",
						Type:  "process",
					},
					"service-b": {
						Id:    "service-b",
						Title: "Service B",
						Type:  "process",
					},
					"service-c": {
						Id:    "service-c",
						Title: "Service C",
						Type:  "process",
					},
					"service-d": {
						Id:    "service-d",
						Title: "Service D",
						Type:  "process",
					},
				},
				CommunicationLinks: map[string]*types.CommunicationLink{
					"link-1": {
						SourceId: "service-a",
						TargetId: "service-b",
						Protocol: "https",
						Usage:    "business",
					},
					"link-2": {
						SourceId: "service-b",
						TargetId: "service-c",
						Protocol: "https",
						Usage:    "business",
					},
					"link-3": {
						SourceId: "service-c",
						TargetId: "service-a",
						Protocol: "https",
						Usage:    "business",
					},
				},
			},
			results: []*ParseResult{},
			check: func(t *testing.T, boundaries []*types.TrustBoundary) {
				assert.NotEmpty(t, boundaries)
				
				// Check for data flow boundaries
				hasDataFlowBoundary := false
				for _, b := range boundaries {
					if contains(b.Tags, "detection:dataflow") {
						hasDataFlowBoundary = true
						// Should contain the connected services
						assert.Contains(t, b.TechnicalAssetsInside, "service-a")
						assert.Contains(t, b.TechnicalAssetsInside, "service-b")
						assert.Contains(t, b.TechnicalAssetsInside, "service-c")
						break
					}
				}
				assert.True(t, hasDataFlowBoundary, "Should detect data flow boundary")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boundaries, err := detector.DetectBoundaries(tt.model, tt.results)
			require.NoError(t, err)
			tt.check(t, boundaries)
		})
	}
}

func TestTrustBoundaryDetector_CalculateTrustLevel(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	tests := []struct {
		name      string
		asset     *types.TechnicalAsset
		wantTrust float64
	}{
		{
			name: "External entity - low trust",
			asset: &types.TechnicalAsset{
				Type: "external-entity",
				Tags: []string{},
			},
			wantTrust: 0.1,
		},
		{
			name: "Process - medium trust",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{},
			},
			wantTrust: 0.6,
		},
		{
			name: "Datastore - higher trust",
			asset: &types.TechnicalAsset{
				Type: "datastore",
				Tags: []string{},
			},
			wantTrust: 0.7,
		},
		{
			name: "Public asset - reduced trust",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{"public"},
			},
			wantTrust: 0.4, // 0.6 - 0.2
		},
		{
			name: "Encrypted asset - increased trust",
			asset: &types.TechnicalAsset{
				Type: "datastore",
				Tags: []string{"encrypted"},
			},
			wantTrust: 0.8, // 0.7 + 0.1
		},
		{
			name: "Authenticated asset - increased trust",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{"authenticated", "encrypted"},
			},
			wantTrust: 0.8, // 0.6 + 0.1 + 0.1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trust := detector.calculateTrustLevel(tt.asset)
			assert.InDelta(t, tt.wantTrust, trust, 0.01)
		})
	}
}

func TestTrustBoundaryDetector_DetermineSecurityZone(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	tests := []struct {
		name     string
		asset    *types.TechnicalAsset
		wantZone string
	}{
		{
			name: "External entity - public zone",
			asset: &types.TechnicalAsset{
				Type: "external-entity",
				Tags: []string{},
			},
			wantZone: "public",
		},
		{
			name: "Asset with zone tag",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{"zone:dmz"},
			},
			wantZone: "dmz",
		},
		{
			name: "Asset with network-zone tag",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{"network-zone:private"},
			},
			wantZone: "private",
		},
		{
			name: "Restricted asset",
			asset: &types.TechnicalAsset{
				Type: "datastore",
				Tags: []string{"restricted"},
			},
			wantZone: "restricted",
		},
		{
			name: "Sensitive asset",
			asset: &types.TechnicalAsset{
				Type: "datastore",
				Tags: []string{"sensitive"},
			},
			wantZone: "restricted",
		},
		{
			name: "Default to private",
			asset: &types.TechnicalAsset{
				Type: "process",
				Tags: []string{},
			},
			wantZone: "private",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := detector.determineSecurityZone(tt.asset)
			assert.Equal(t, tt.wantZone, zone)
		})
	}
}

func TestTrustBoundaryDetector_CalculateOverlap(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	tests := []struct {
		name        string
		boundary1   *types.TrustBoundary
		boundary2   *types.TrustBoundary
		wantOverlap float64
	}{
		{
			name: "No overlap",
			boundary1: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b", "c"},
			},
			boundary2: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"d", "e", "f"},
			},
			wantOverlap: 0.0,
		},
		{
			name: "Partial overlap",
			boundary1: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b", "c"},
			},
			boundary2: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"b", "c", "d"},
			},
			wantOverlap: 0.5, // 2 shared out of 4 unique
		},
		{
			name: "Complete overlap",
			boundary1: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b", "c"},
			},
			boundary2: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b", "c"},
			},
			wantOverlap: 1.0,
		},
		{
			name: "One subset of other",
			boundary1: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b"},
			},
			boundary2: &types.TrustBoundary{
				TechnicalAssetsInside: []string{"a", "b", "c", "d"},
			},
			wantOverlap: 0.5, // 2 shared out of 4 unique
		},
		{
			name: "Empty boundaries",
			boundary1: &types.TrustBoundary{
				TechnicalAssetsInside: []string{},
			},
			boundary2: &types.TrustBoundary{
				TechnicalAssetsInside: []string{},
			},
			wantOverlap: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overlap := detector.calculateOverlap(tt.boundary1, tt.boundary2)
			assert.InDelta(t, tt.wantOverlap, overlap, 0.01)
		})
	}
}

func TestTrustBoundaryDetector_CalculateBoundaryScore(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	tests := []struct {
		name         string
		boundary     *types.TrustBoundary
		model        *types.Model
		minScore     float64
		maxScore     float64
	}{
		{
			name: "High score - network boundary with critical assets",
			boundary: &types.TrustBoundary{
				Type: "network-cloud-provider",
				Tags: []string{"detection:network"},
				TechnicalAssetsInside: []string{"db1", "db2", "web1"},
			},
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"db1":  {Id: "db1", Type: "datastore"},
					"db2":  {Id: "db2", Type: "datastore"},
					"web1": {Id: "web1", Type: "process"},
				},
			},
			minScore: 0.7,
			maxScore: 1.0,
		},
		{
			name: "Medium score - execution environment",
			boundary: &types.TrustBoundary{
				Type: "execution-environment",
				Tags: []string{"detection:iam"},
				TechnicalAssetsInside: []string{"service1", "service2"},
			},
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"service1": {Id: "service1", Type: "process"},
					"service2": {Id: "service2", Type: "process"},
				},
			},
			minScore: 0.3,
			maxScore: 0.7,
		},
		{
			name: "Low score - small boundary",
			boundary: &types.TrustBoundary{
				Type: "execution-environment",
				Tags: []string{"detection:dataflow"},
				TechnicalAssetsInside: []string{"service1"},
			},
			model: &types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"service1": {Id: "service1", Type: "process"},
				},
			},
			minScore: 0.2,
			maxScore: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := detector.calculateBoundaryScore(tt.boundary, tt.model)
			assert.GreaterOrEqual(t, score, tt.minScore)
			assert.LessOrEqual(t, score, tt.maxScore)
		})
	}
}

func TestTrustBoundaryDetector_MergeBoundaries(t *testing.T) {
	detector := NewTrustBoundaryDetector()

	boundaries := []*types.TrustBoundary{
		{
			Id:                    "b1",
			Title:                 "Boundary 1",
			TechnicalAssetsInside: []string{"a", "b", "c"},
		},
		{
			Id:                    "b2",
			Title:                 "Boundary 2",
			TechnicalAssetsInside: []string{"b", "c", "d"},  // 66% overlap with b1
		},
		{
			Id:                    "b3",
			Title:                 "Boundary 3",
			TechnicalAssetsInside: []string{"e", "f", "g"},  // No overlap
		},
		{
			Id:                    "b4",
			Title:                 "Boundary 4",
			TechnicalAssetsInside: []string{"a", "b", "c"},  // 100% overlap with b1
		},
	}

	merged := detector.mergeBoundaries(boundaries)

	// Should merge b1 with b4 (100% overlap)
	// Should keep b2 separate (66% overlap, below 80% threshold)
	// Should keep b3 separate (no overlap)
	assert.Len(t, merged, 3)

	// Check that highly overlapping boundaries were merged
	hasMerged := false
	for _, b := range merged {
		if strings.Contains(b.Id, "b1") && strings.Contains(b.Id, "b4") {
			hasMerged = true
			// Should contain all unique assets from both
			assert.Contains(t, b.TechnicalAssetsInside, "a")
			assert.Contains(t, b.TechnicalAssetsInside, "b")
			assert.Contains(t, b.TechnicalAssetsInside, "c")
		}
	}
	assert.True(t, hasMerged, "Should merge boundaries with high overlap")
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}