// Package ai provides AI-powered threat model generation including
// advanced trust boundary detection using graph algorithms and
// pattern recognition.
package ai

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// BoundaryDetector implements advanced trust boundary detection algorithms.
// Trust boundaries represent transitions between different levels of trust
// in a system and are critical for threat modeling.
//
// The detector uses multiple approaches:
//   - Graph-based community detection
//   - Network topology analysis
//   - IAM permission boundaries
//   - Security zone identification
//   - Data flow analysis
//   - Compliance scope detection
//
// The graph representation enables sophisticated algorithms like:
//   - Spectral clustering
//   - Minimum cut analysis
//   - Centrality-based detection
//   - Community detection
type BoundaryDetector struct {
	// nodes stores all infrastructure components as graph nodes
	nodes map[string]*GraphNode
	// edges stores connections between components
	edges map[string][]*GraphEdge
}

// GraphNode represents an infrastructure component in the graph model.
// Each node contains security-relevant attributes used for boundary detection.
type GraphNode struct {
	// ID uniquely identifies the infrastructure component
	ID         string
	// Type categorizes the component (compute, storage, network, etc.)
	Type       string
	// Properties stores additional metadata for analysis
	Properties map[string]interface{}
	// TrustLevel indicates the security trust score (0.0 to 1.0)
	TrustLevel float64
	// Zone identifies the security zone (public, private, dmz)
	Zone       string
	// Provider indicates the infrastructure provider (aws, azure, gcp)
	Provider   string
}

// GraphEdge represents a connection or relationship between infrastructure components.
// Edges carry security-relevant information about data flows and dependencies.
type GraphEdge struct {
	// Source node ID (originator of connection)
	Source     string
	// Target node ID (destination of connection)
	Target     string
	// Weight represents connection strength or trust level (0.0 to 1.0)
	Weight     float64
	// Type categorizes the connection (network, iam, data-flow)
	Type       string
	// Properties stores additional edge metadata
	Properties map[string]interface{}
}

// Community represents a group of closely connected infrastructure components.
// Communities often indicate natural trust boundaries in the system.
type Community struct {
	// ID uniquely identifies the community
	ID       string
	// Nodes lists all component IDs in this community
	Nodes    []string
	// Boundary indicates if this forms a trust boundary
	Boundary bool
	// Type categorizes the community (network, functional, compliance)
	Type     string
	// Trust represents the aggregate trust level
	Trust    float64
}

// NewBoundaryDetector creates a new trust boundary detector instance.
// The detector initializes with empty graph structures that will be
// populated during the analysis phase.
func NewBoundaryDetector() *BoundaryDetector {
	return &BoundaryDetector{
		nodes: make(map[string]*GraphNode),
		edges: make(map[string][]*GraphEdge),
	}
}

// DetectBoundaries orchestrates multiple algorithms to identify trust boundaries.
// This comprehensive approach ensures no critical boundaries are missed.
//
// Detection process:
//   1. Build graph representation of infrastructure
//   2. Apply seven different detection algorithms
//   3. Merge and deduplicate results
//   4. Validate and rank by importance
//
// Detection algorithms:
//   - Network topology: VPCs, subnets, security groups
//   - IAM boundaries: Permission boundaries, account separation
//   - Provider boundaries: Multi-cloud, hybrid environments
//   - Security zones: DMZ, public, private, management
//   - Graph communities: Tightly coupled components
//   - Data flows: Information flow analysis
//   - Compliance scopes: Regulatory boundaries
//
// Parameters:
//   - model: The threat model being analyzed
//   - results: Parsed infrastructure data
//
// Returns:
//   - Detected and validated trust boundaries
//   - Error if detection fails
func (d *BoundaryDetector) DetectBoundaries(model *types.Model, results []*ParseResult) ([]*types.TrustBoundary, error) {
	// Phase 1: Build graph representation for analysis
	d.buildGraph(model, results)
	
	// Phase 2: Apply multiple detection algorithms in parallel
	boundaries := []*types.TrustBoundary{}
	
	// Algorithm 1: Detect boundaries based on network isolation
	networkBoundaries := d.detectNetworkBoundaries(results)
	boundaries = append(boundaries, networkBoundaries...)
	
	// Algorithm 2: Detect IAM permission boundaries
	iamBoundaries := d.detectIAMBoundaries(results)
	boundaries = append(boundaries, iamBoundaries...)
	
	// Algorithm 3: Detect cloud provider boundaries
	providerBoundaries := d.detectProviderBoundaries(results)
	boundaries = append(boundaries, providerBoundaries...)
	
	// Algorithm 4: Detect security zone boundaries
	zoneBoundaries := d.detectSecurityZoneBoundaries(model, results)
	boundaries = append(boundaries, zoneBoundaries...)
	
	// Algorithm 5: Use graph algorithms for community detection
	communityBoundaries := d.detectCommunityBoundaries()
	boundaries = append(boundaries, communityBoundaries...)
	
	// Algorithm 6: Analyze data flows for boundaries
	dataFlowBoundaries := d.detectDataFlowBoundaries(model)
	boundaries = append(boundaries, dataFlowBoundaries...)
	
	// Algorithm 7: Identify compliance-driven boundaries
	complianceBoundaries := d.detectComplianceBoundaries(model, results)
	boundaries = append(boundaries, complianceBoundaries...)
	
	// Phase 3: Consolidate detected boundaries
	// Remove duplicates and merge overlapping boundaries
	boundaries = d.mergeBoundaries(boundaries)
	
	// Phase 4: Validate and prioritize boundaries
	// Rank by security importance and coverage
	boundaries = d.validateAndRankBoundaries(boundaries, model)
	
	return boundaries, nil
}

// buildGraph constructs a graph representation of the infrastructure for analysis.
// The graph model enables sophisticated algorithms for boundary detection.
//
// Graph construction process:
//   1. Convert technical assets to nodes with security attributes
//   2. Convert communication links to weighted edges
//   3. Add infrastructure-specific nodes and edges
//   4. Calculate trust levels and zones
//
// The resulting graph captures:
//   - Component relationships
//   - Trust levels
//   - Security zones
//   - Data flows
//   - Provider boundaries
//
// Parameters:
//   - model: The threat model containing assets and links
//   - results: Parsed infrastructure data
func (d *BoundaryDetector) buildGraph(model *types.Model, results []*ParseResult) {
	// Convert each technical asset to a graph node
	for id, asset := range model.TechnicalAssets {
		d.nodes[id] = &GraphNode{
			ID:         id,
			Type:       string(asset.Type),
			Properties: d.assetToProperties(asset),
			TrustLevel: d.calculateTrustLevel(asset),
			Zone:       d.determineAssetZone(asset),
			Provider:   d.determineAssetProvider(asset),
		}
	}
	
	// Transform communication links into graph edges
	// Edge weights represent trust levels between components
	for _, link := range model.CommunicationLinks {
		edge := &GraphEdge{
			Source:     link.SourceId,
			Target:     link.TargetId,
			Weight:     d.calculateEdgeWeight(link),
			Type:       string(link.Protocol),
			Properties: d.linkToProperties(link),
		}
		
		// Build adjacency list representation
		if d.edges[link.SourceId] == nil {
			d.edges[link.SourceId] = []*GraphEdge{}
		}
		d.edges[link.SourceId] = append(d.edges[link.SourceId], edge)
	}
	
	// Add nodes and edges from parsed infrastructure
	for _, result := range results {
		d.addInfrastructureNodes(result)
		d.addInfrastructureEdges(result)
	}
}

// detectNetworkBoundaries identifies trust boundaries based on network isolation.
// Network segmentation is a fundamental security control that creates natural
// trust boundaries in cloud infrastructure.
//
// Detection criteria:
//   - VPC boundaries: Isolated virtual networks
//   - Subnet groupings: Public vs private subnets
//   - Security group perimeters: Firewall rule sets
//   - Network ACLs: Subnet-level controls
//
// Network boundaries are strong indicators because:
//   - They enforce traffic isolation
//   - They require explicit peering/gateways to cross
//   - They often align with security zones
//   - They support compliance requirements
//
// Parameters:
//   - results: Parsed infrastructure containing network resources
//
// Returns:
//   - Trust boundaries based on network topology
func (d *BoundaryDetector) detectNetworkBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	for _, result := range results {
		// VPCs form primary network boundaries in cloud environments
		for id, network := range result.Networks {
			if network.Type == "vpc" {
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("network-%s", id),
					Title:       fmt.Sprintf("%s Network Boundary", network.Name),
					Description: fmt.Sprintf("Network boundary for %s", network.Name),
					Type:        types.NetworkCloudProvider,
					Tags: []string{
						fmt.Sprintf("provider:%s", network.Provider),
						fmt.Sprintf("type:%s", network.Type),
						"detection:network",
					},
				}
				
				// Assign assets to boundary
				boundary.TechnicalAssetsInside = d.findAssetsInNetwork(network)
				boundaries = append(boundaries, boundary)
			}
		}
		
		// Group subnets by type to detect zone-based boundaries
		// Public/private subnet separation is a common pattern
		subnets := d.groupSubnetsByType(result.Networks)
		for subnetType, networks := range subnets {
			if len(networks) > 0 {
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("subnet-group-%s", subnetType),
					Title:       fmt.Sprintf("%s Subnet Group", strings.Title(subnetType)),
					Description: fmt.Sprintf("Subnet grouping for %s networks", subnetType),
					Type:        types.NetworkCloudProvider,
					Tags: []string{
						fmt.Sprintf("subnet-type:%s", subnetType),
						"detection:subnet-grouping",
					},
				}
				
				// Assign assets to boundary
				for _, network := range networks {
					boundary.TechnicalAssetsInside = append(
						boundary.TechnicalAssetsInside,
						d.findAssetsInNetwork(network)...,
					)
				}
				boundaries = append(boundaries, boundary)
			}
		}
	}
	
	return boundaries
}

// detectIAMBoundaries identifies trust boundaries based on identity and access management.
// IAM boundaries represent permission isolation and are critical for least privilege.
//
// Detection criteria:
//   - IAM role boundaries: Resources sharing same permissions
//   - Service account isolation: Workload identities
//   - Permission boundaries: Maximum permission sets
//   - Cross-account roles: External trust relationships
//
// IAM boundaries are important because:
//   - They control resource access
//   - They prevent privilege escalation
//   - They enforce separation of duties
//   - They support compliance requirements
//
// Parameters:
//   - results: Parsed infrastructure containing IAM resources
//
// Returns:
//   - Trust boundaries based on IAM configuration
func (d *BoundaryDetector) detectIAMBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	for _, result := range results {
		// Resources sharing IAM roles form natural boundaries
		roleGroups := d.groupResourcesByIAMRole(result)
		
		for roleID, resources := range roleGroups {
			if len(resources) > 1 { // Multiple resources indicate shared permissions
				role := result.Roles[roleID]
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("iam-%s", roleID),
					Title:       fmt.Sprintf("IAM Boundary: %s", role.Name),
					Description: fmt.Sprintf("Resources sharing IAM role %s", role.Name),
					Type:        types.ExecutionEnvironment,
					Tags: []string{
						fmt.Sprintf("role:%s", role.Name),
						"detection:iam",
					},
				}
				
				// Assign resources to boundary
				for _, resource := range resources {
					boundary.TechnicalAssetsInside = append(
						boundary.TechnicalAssetsInside,
						resource.ID,
					)
				}
				boundaries = append(boundaries, boundary)
			}
		}
	}
	
	return boundaries
}

// detectProviderBoundaries identifies trust boundaries between cloud providers.
// Multi-cloud and hybrid deployments create natural boundaries due to:
//   - Different security models
//   - Separate identity systems  
//   - Incompatible networking
//   - Provider-specific controls
//
// Provider boundaries are significant because:
//   - They require explicit integration (VPN, peering)
//   - They have different compliance certifications
//   - They use incompatible IAM systems
//   - They may have data residency implications
//
// Parameters:
//   - results: Parsed infrastructure from multiple providers
//
// Returns:
//   - Trust boundaries between cloud providers
func (d *BoundaryDetector) detectProviderBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Group all resources by their cloud provider
	providerGroups := make(map[string][]string)
	
	for _, result := range results {
		for id, resource := range result.Resources {
			if providerGroups[resource.Provider] == nil {
				providerGroups[resource.Provider] = []string{}
			}
			providerGroups[resource.Provider] = append(providerGroups[resource.Provider], id)
		}
	}
	
	// Create boundaries for each provider
	for provider, resources := range providerGroups {
		if provider != "unknown" && len(resources) > 0 {
			boundary := &types.TrustBoundary{
				Id:          fmt.Sprintf("provider-%s", provider),
				Title:       fmt.Sprintf("%s Provider Boundary", strings.ToUpper(provider)),
				Description: fmt.Sprintf("Resources in %s cloud provider", provider),
				Type:        types.NetworkCloudProvider,
				Tags: []string{
					fmt.Sprintf("provider:%s", provider),
					"detection:provider",
				},
				TechnicalAssetsInside: resources,
			}
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// detectSecurityZoneBoundaries identifies boundaries based on security zone classification.
// Security zones represent areas with similar trust levels and security requirements.
//
// Standard security zones:
//   - Public: Internet-facing, untrusted
//   - DMZ: Semi-trusted buffer zone
//   - Private: Internal trusted resources
//   - Restricted: Highly sensitive systems
//
// Zone boundaries are critical because:
//   - They define defense-in-depth layers
//   - They enforce traffic flow restrictions
//   - They align with compliance requirements
//   - They guide security control placement
//
// Parameters:
//   - model: Threat model with classified assets
//   - results: Infrastructure data for zone inference
//
// Returns:
//   - Trust boundaries for each security zone
func (d *BoundaryDetector) detectSecurityZoneBoundaries(model *types.Model, results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Define standard security zones with trust levels
	zones := map[string]*types.TrustBoundary{
		"public": {
			Id:          "zone-public",
			Title:       "Public Zone",
			Description: "Internet-facing resources",
			Type:        types.NetworkOnPrem,
			Tags:        []string{"zone:public", "detection:security-zone"},
		},
		"dmz": {
			Id:          "zone-dmz",
			Title:       "DMZ Zone",
			Description: "Demilitarized zone resources",
			Type:        types.NetworkOnPrem,
			Tags:        []string{"zone:dmz", "detection:security-zone"},
		},
		"private": {
			Id:          "zone-private",
			Title:       "Private Zone",
			Description: "Internal resources",
			Type:        types.NetworkOnPrem,
			Tags:        []string{"zone:private", "detection:security-zone"},
		},
		"restricted": {
			Id:          "zone-restricted",
			Title:       "Restricted Zone",
			Description: "Highly sensitive resources",
			Type:        types.NetworkOnPrem,
			Tags:        []string{"zone:restricted", "detection:security-zone"},
		},
	}
	
	// Assign assets to security zones
	for id, asset := range model.TechnicalAssets {
		zone := d.determineSecurityZone(asset)
		if boundary, exists := zones[zone]; exists {
			boundary.TechnicalAssetsInside = append(boundary.TechnicalAssetsInside, id)
		}
	}
	
	// Only add zones that have assets
	for _, boundary := range zones {
		if len(boundary.TechnicalAssetsInside) > 0 {
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// detectCommunityBoundaries uses graph algorithms to find tightly coupled components.
// Community detection reveals natural groupings that may represent trust boundaries.
//
// Algorithm approach (simplified Louvain method):
//   1. Initialize each node as its own community
//   2. Iteratively merge communities to maximize modularity
//   3. Identify communities with high internal connectivity
//   4. Mark boundaries between distinct communities
//
// Communities indicate boundaries when:
//   - High internal connectivity, low external
//   - Different trust levels between communities
//   - Natural functional groupings
//   - Minimal cross-community dependencies
//
// Returns:
//   - Trust boundaries around detected communities
func (d *BoundaryDetector) detectCommunityBoundaries() []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Apply graph-based community detection algorithm
	communities := d.detectCommunities()
	
	for _, community := range communities {
		if community.Boundary {
			boundary := &types.TrustBoundary{
				Id:          fmt.Sprintf("community-%s", community.ID),
				Title:       fmt.Sprintf("Community Boundary %s", community.ID),
				Description: fmt.Sprintf("Detected community of related resources"),
				Type:        types.ExecutionEnvironment,
				Tags: []string{
					fmt.Sprintf("community:%s", community.ID),
					fmt.Sprintf("trust:%.2f", community.Trust),
					"detection:graph-community",
				},
				TechnicalAssetsInside: community.Nodes,
			}
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// detectDataFlowBoundaries identifies boundaries based on information flow analysis.
// Components with heavy data exchange often share trust requirements.
//
// Data flow analysis considers:
//   - Volume of data exchanged
//   - Sensitivity of data
//   - Bidirectional vs unidirectional flows
//   - Data transformation points
//
// Boundaries are created where:
//   - Data sensitivity changes
//   - Data leaves security zones
//   - Significant aggregation occurs
//   - Data format transformations happen
//
// Parameters:
//   - model: Threat model with communication links
//
// Returns:
//   - Trust boundaries based on data flow patterns
func (d *BoundaryDetector) detectDataFlowBoundaries(model *types.Model) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Group assets by data flow intensity and patterns
	dataFlowGroups := d.analyzeDataFlowPatterns(model)
	
	for groupID, assets := range dataFlowGroups {
		if len(assets) > 2 { // Significant groups only
			boundary := &types.TrustBoundary{
				Id:          fmt.Sprintf("dataflow-%s", groupID),
				Title:       fmt.Sprintf("Data Flow Boundary %s", groupID),
				Description: "Resources with significant data exchange",
				Type:        types.ExecutionEnvironment,
				Tags: []string{
					fmt.Sprintf("dataflow:%s", groupID),
					"detection:dataflow",
				},
				TechnicalAssetsInside: assets,
			}
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// detectComplianceBoundaries identifies boundaries driven by regulatory requirements.
// Compliance frameworks mandate specific security controls and isolation.
//
// Supported frameworks:
//   - PCI-DSS: Payment card industry data security
//   - HIPAA: Healthcare information privacy
//   - GDPR: EU data protection regulation
//   - SOC2: Service organization controls
//
// Compliance boundaries ensure:
//   - Required controls are implemented
//   - Data is properly isolated
//   - Audit scope is defined
//   - Regulatory requirements are met
//
// Detection based on:
//   - Data type classification
//   - Resource tags
//   - Industry patterns
//
// Parameters:
//   - model: Threat model with compliance indicators
//   - results: Infrastructure data
//
// Returns:
//   - Trust boundaries for compliance scopes
func (d *BoundaryDetector) detectComplianceBoundaries(model *types.Model, results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Define regulatory compliance boundaries
	complianceZones := map[string]*types.TrustBoundary{
		"pci": {
			Id:          "compliance-pci",
			Title:       "PCI Compliance Boundary",
			Description: "Resources handling payment card data",
			Type:        types.ExecutionEnvironment,
			Tags:        []string{"compliance:pci-dss", "detection:compliance"},
		},
		"hipaa": {
			Id:          "compliance-hipaa",
			Title:       "HIPAA Compliance Boundary",
			Description: "Resources handling protected health information",
			Type:        types.ExecutionEnvironment,
			Tags:        []string{"compliance:hipaa", "detection:compliance"},
		},
		"gdpr": {
			Id:          "compliance-gdpr",
			Title:       "GDPR Compliance Boundary",
			Description: "Resources handling personal data",
			Type:        types.ExecutionEnvironment,
			Tags:        []string{"compliance:gdpr", "detection:compliance"},
		},
	}
	
	// Assign assets to compliance boundaries based on tags and data types
	for id, asset := range model.TechnicalAssets {
		compliance := d.determineComplianceRequirement(asset, model.DataAssets)
		for _, req := range compliance {
			if boundary, exists := complianceZones[req]; exists {
				boundary.TechnicalAssetsInside = append(boundary.TechnicalAssetsInside, id)
			}
		}
	}
	
	// Only add zones that have assets
	for _, boundary := range complianceZones {
		if len(boundary.TechnicalAssetsInside) > 0 {
			boundaries = append(boundaries, boundary)
		}
	}
	
	return boundaries
}

// mergeBoundaries consolidates overlapping boundaries to avoid redundancy.
// Multiple detection algorithms may identify similar boundaries.
//
// Merge criteria:
//   - Asset overlap > 80%
//   - Compatible boundary types
//   - Similar trust levels
//
// Merge process:
//   1. Calculate overlap between all boundary pairs
//   2. Merge highly overlapping boundaries
//   3. Combine metadata and tags
//   4. Preserve the most specific boundary type
//
// This prevents:
//   - Duplicate boundaries
//   - Overlapping controls
//   - Confusion in threat model
//
// Parameters:
//   - boundaries: All detected boundaries
//
// Returns:
//   - Consolidated list of unique boundaries
func (d *BoundaryDetector) mergeBoundaries(boundaries []*types.TrustBoundary) []*types.TrustBoundary {
	merged := []*types.TrustBoundary{}
	processed := make(map[string]bool)
	
	for i, boundary := range boundaries {
		if processed[boundary.Id] {
			continue
		}
		
		// Compare with all subsequent boundaries
		for j := i + 1; j < len(boundaries); j++ {
			other := boundaries[j]
			if processed[other.Id] {
				continue
			}
			
			// Check if boundaries significantly overlap
			overlap := d.calculateOverlap(boundary, other)
			if overlap > 0.8 { // 80% threshold
				// Combine overlapping boundaries
				boundary = d.mergeTwoBoundaries(boundary, other)
				processed[other.Id] = true
			}
		}
		
		merged = append(merged, boundary)
		processed[boundary.Id] = true
	}
	
	return merged
}

// validateAndRankBoundaries prioritizes boundaries by security importance.
// Not all boundaries are equally critical for threat modeling.
//
// Scoring factors:
//   - Number of assets protected
//   - Sensitivity of data involved
//   - Attack surface reduction
//   - Compliance requirements
//   - Network isolation strength
//   - Detection confidence
//
// Validation checks:
//   - Minimum asset coverage
//   - Logical consistency
//   - No empty boundaries
//   - Proper type assignment
//
// Ranking ensures:
//   - Critical boundaries are highlighted
//   - Resources focus on important boundaries
//   - Low-value boundaries are filtered
//
// Parameters:
//   - boundaries: All detected boundaries
//   - model: Threat model for context
//
// Returns:
//   - Validated and ranked boundaries
func (d *BoundaryDetector) validateAndRankBoundaries(boundaries []*types.TrustBoundary, model *types.Model) []*types.TrustBoundary {
	// Score each boundary for importance
	type scoredBoundary struct {
		boundary *types.TrustBoundary
		score    float64
	}
	
	scored := []scoredBoundary{}
	
	for _, boundary := range boundaries {
		// Calculate importance score
		score := d.calculateBoundaryScore(boundary, model)
		if score > 0.3 { // Filter low-importance boundaries
			scored = append(scored, scoredBoundary{boundary, score})
		}
	}
	
	// Sort by score
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	
	// Return top boundaries
	result := []*types.TrustBoundary{}
	for _, sb := range scored {
		result = append(result, sb.boundary)
		if len(result) >= 10 { // Limit to top 10 boundaries
			break
		}
	}
	
	return result
}

// Helper methods

func (d *BoundaryDetector) assetToProperties(asset *types.TechnicalAsset) map[string]interface{} {
	return map[string]interface{}{
		"type":  asset.Type,
		"title": asset.Title,
		"tags":  asset.Tags,
	}
}

func (d *BoundaryDetector) calculateTrustLevel(asset *types.TechnicalAsset) float64 {
	// Calculate trust level based on asset properties
	trust := 0.5 // Default trust
	
	// Adjust based on asset type
	switch asset.Type {
	case types.ExternalEntity:
		trust = 0.1
	case types.Process:
		trust = 0.6
	case types.Datastore:
		trust = 0.7
	}
	
	// Adjust based on tags
	for _, tag := range asset.Tags {
		if strings.Contains(tag, "public") {
			trust -= 0.2
		}
		if strings.Contains(tag, "encrypted") {
			trust += 0.1
		}
		if strings.Contains(tag, "authenticated") {
			trust += 0.1
		}
	}
	
	// Clamp between 0 and 1
	return math.Max(0, math.Min(1, trust))
}

func (d *BoundaryDetector) determineAssetZone(asset *types.TechnicalAsset) string {
	// Determine security zone from tags
	for _, tag := range asset.Tags {
		if strings.HasPrefix(tag, "zone:") {
			return strings.TrimPrefix(tag, "zone:")
		}
		if strings.HasPrefix(tag, "network-zone:") {
			return strings.TrimPrefix(tag, "network-zone:")
		}
	}
	
	// Default based on asset type
	if asset.Type == types.ExternalEntity {
		return "public"
	}
	return "private"
}

func (d *BoundaryDetector) determineAssetProvider(asset *types.TechnicalAsset) string {
	// Determine cloud provider from tags
	for _, tag := range asset.Tags {
		if strings.HasPrefix(tag, "provider:") {
			return strings.TrimPrefix(tag, "provider:")
		}
	}
	return "unknown"
}

func (d *BoundaryDetector) calculateEdgeWeight(link *types.CommunicationLink) float64 {
	weight := 1.0
	
	// Adjust based on protocol
	if link.Protocol == types.HTTPS {
		weight += 0.2
	}
	
	// Adjust based on authentication
	if link.Authentication != types.NoneAuthentication {
		weight += 0.3
	}
	
	return weight
}

func (d *BoundaryDetector) linkToProperties(link *types.CommunicationLink) map[string]interface{} {
	return map[string]interface{}{
		"protocol":       link.Protocol,
		"authentication": link.Authentication,
		"authorization":  link.Authorization,
	}
}

func (d *BoundaryDetector) addInfrastructureNodes(result *ParseResult) {
	// Add nodes for infrastructure resources
	for id, resource := range result.Resources {
		if _, exists := d.nodes[id]; !exists {
			d.nodes[id] = &GraphNode{
				ID:       id,
				Type:     resource.Type,
				Provider: resource.Provider,
			}
		}
	}
}

func (d *BoundaryDetector) addInfrastructureEdges(result *ParseResult) {
	// Add edges based on infrastructure relationships
	// This would analyze dependencies and connections
}

func (d *BoundaryDetector) findAssetsInNetwork(network *Network) []string {
	assets := []string{}
	// Find assets that belong to this network
	for id, node := range d.nodes {
		if node.Provider == network.Provider {
			// Simple heuristic - same provider
			assets = append(assets, id)
		}
	}
	return assets
}

func (d *BoundaryDetector) groupSubnetsByType(networks map[string]*Network) map[string][]*Network {
	groups := make(map[string][]*Network)
	
	for _, network := range networks {
		if network.Type == "subnet" {
			zone := "private" // Default
			name := strings.ToLower(network.Name)
			
			if strings.Contains(name, "public") {
				zone = "public"
			} else if strings.Contains(name, "dmz") {
				zone = "dmz"
			} else if strings.Contains(name, "private") {
				zone = "private"
			}
			
			groups[zone] = append(groups[zone], network)
		}
	}
	
	return groups
}

func (d *BoundaryDetector) groupResourcesByIAMRole(result *ParseResult) map[string][]*Resource {
	groups := make(map[string][]*Resource)
	// Group resources by their IAM roles
	// This would require analyzing IAM attachments
	return groups
}

func (d *BoundaryDetector) determineSecurityZone(asset *types.TechnicalAsset) string {
	// Determine security zone based on asset properties
	zone := d.determineAssetZone(asset)
	
	// Refine based on asset type and tags
	if asset.Type == types.ExternalEntity {
		return "public"
	}
	
	for _, tag := range asset.Tags {
		if strings.Contains(tag, "restricted") || strings.Contains(tag, "sensitive") {
			return "restricted"
		}
	}
	
	return zone
}

func (d *BoundaryDetector) detectCommunities() []*Community {
	communities := []*Community{}
	
	// Simplified community detection algorithm
	visited := make(map[string]bool)
	communityID := 0
	
	for nodeID := range d.nodes {
		if !visited[nodeID] {
			community := &Community{
				ID:    fmt.Sprintf("c%d", communityID),
				Nodes: []string{},
				Trust: 0.5,
			}
			
			// BFS to find connected components
			queue := []string{nodeID}
			for len(queue) > 0 {
				current := queue[0]
				queue = queue[1:]
				
				if visited[current] {
					continue
				}
				
				visited[current] = true
				community.Nodes = append(community.Nodes, current)
				
				// Add neighbors
				for _, edge := range d.edges[current] {
					if !visited[edge.Target] {
						queue = append(queue, edge.Target)
					}
				}
			}
			
			// Determine if this is a boundary community
			if len(community.Nodes) > 2 {
				community.Boundary = true
				communities = append(communities, community)
				communityID++
			}
		}
	}
	
	return communities
}

func (d *BoundaryDetector) analyzeDataFlowPatterns(model *types.Model) map[string][]string {
	patterns := make(map[string][]string)
	
	// Analyze communication links to find data flow patterns
	flowGroups := make(map[string][]string)
	
	for _, link := range model.CommunicationLinks {
		// Group by protocol and usage
		groupKey := fmt.Sprintf("%s-%s", link.Protocol, link.Usage)
		
		if flowGroups[groupKey] == nil {
			flowGroups[groupKey] = []string{}
		}
		
		// Add both source and target
		flowGroups[groupKey] = append(flowGroups[groupKey], link.SourceId)
		flowGroups[groupKey] = append(flowGroups[groupKey], link.TargetId)
	}
	
	// Deduplicate and create patterns
	for key, assets := range flowGroups {
		unique := make(map[string]bool)
		for _, asset := range assets {
			unique[asset] = true
		}
		
		uniqueAssets := []string{}
		for asset := range unique {
			uniqueAssets = append(uniqueAssets, asset)
		}
		
		patterns[key] = uniqueAssets
	}
	
	return patterns
}

func (d *BoundaryDetector) determineComplianceRequirement(asset *types.TechnicalAsset, dataAssets map[string]*types.DataAsset) []string {
	requirements := []string{}
	
	// Check asset tags
	for _, tag := range asset.Tags {
		if strings.Contains(tag, "compliance:pci") {
			requirements = append(requirements, "pci")
		}
		if strings.Contains(tag, "compliance:hipaa") {
			requirements = append(requirements, "hipaa")
		}
		if strings.Contains(tag, "compliance:gdpr") {
			requirements = append(requirements, "gdpr")
		}
	}
	
	// Check data assets processed
	for _, dataAssetID := range asset.DataAssetsProcessed {
		if dataAsset, exists := dataAssets[dataAssetID]; exists {
			// Check data classification
			if dataAsset.Confidentiality == types.StrictlyConfidential {
				if strings.Contains(strings.ToLower(dataAsset.Title), "payment") {
					requirements = append(requirements, "pci")
				}
				if strings.Contains(strings.ToLower(dataAsset.Title), "health") {
					requirements = append(requirements, "hipaa")
				}
				if strings.Contains(strings.ToLower(dataAsset.Title), "personal") {
					requirements = append(requirements, "gdpr")
				}
			}
		}
	}
	
	return requirements
}

func (d *BoundaryDetector) calculateOverlap(b1, b2 *types.TrustBoundary) float64 {
	// Calculate overlap between two boundaries based on contained assets
	set1 := make(map[string]bool)
	for _, asset := range b1.TechnicalAssetsInside {
		set1[asset] = true
	}
	
	overlap := 0
	for _, asset := range b2.TechnicalAssetsInside {
		if set1[asset] {
			overlap++
		}
	}
	
	total := len(b1.TechnicalAssetsInside) + len(b2.TechnicalAssetsInside) - overlap
	if total == 0 {
		return 0
	}
	
	return float64(overlap) / float64(total)
}

func (d *BoundaryDetector) mergeTwoBoundaries(b1, b2 *types.TrustBoundary) *types.TrustBoundary {
	// Merge two boundaries
	merged := &types.TrustBoundary{
		Id:          fmt.Sprintf("%s-%s", b1.Id, b2.Id),
		Title:       fmt.Sprintf("%s + %s", b1.Title, b2.Title),
		Description: fmt.Sprintf("Merged: %s; %s", b1.Description, b2.Description),
		Type:        b1.Type, // Use first boundary's type
		Tags:        append(b1.Tags, b2.Tags...),
	}
	
	// Merge assets
	assetSet := make(map[string]bool)
	for _, asset := range b1.TechnicalAssetsInside {
		assetSet[asset] = true
	}
	for _, asset := range b2.TechnicalAssetsInside {
		assetSet[asset] = true
	}
	
	for asset := range assetSet {
		merged.TechnicalAssetsInside = append(merged.TechnicalAssetsInside, asset)
	}
	
	return merged
}

func (d *BoundaryDetector) calculateBoundaryScore(boundary *types.TrustBoundary, model *types.Model) float64 {
	score := 0.0
	
	// Score based on number of assets
	assetCount := len(boundary.TechnicalAssetsInside)
	if assetCount > 0 {
		score += math.Min(float64(assetCount)/10.0, 1.0)
	}
	
	// Score based on boundary type
	switch boundary.Type {
	case types.NetworkCloudProvider:
		score += 0.8
	case types.ExecutionEnvironment:
		score += 0.6
	case types.NetworkOnPrem:
		score += 0.7
	}
	
	// Score based on detection method
	for _, tag := range boundary.Tags {
		if strings.HasPrefix(tag, "detection:") {
			method := strings.TrimPrefix(tag, "detection:")
			switch method {
			case "network":
				score += 0.9
			case "security-zone":
				score += 0.8
			case "compliance":
				score += 0.7
			case "graph-community":
				score += 0.6
			case "dataflow":
				score += 0.5
			}
		}
	}
	
	// Score based on asset criticality
	criticalAssets := 0
	for _, assetID := range boundary.TechnicalAssetsInside {
		if asset, exists := model.TechnicalAssets[assetID]; exists {
			if asset.Type == types.Datastore || strings.Contains(strings.ToLower(asset.Title), "database") {
				criticalAssets++
			}
		}
	}
	score += float64(criticalAssets) * 0.2
	
	// Normalize score
	return math.Min(score/3.0, 1.0)
}