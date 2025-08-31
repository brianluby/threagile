package ai

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// BoundaryDetector implements advanced trust boundary detection algorithms
type BoundaryDetector struct {
	// Graph representation of the infrastructure
	nodes map[string]*GraphNode
	edges map[string][]*GraphEdge
}

// GraphNode represents a node in the infrastructure graph
type GraphNode struct {
	ID         string
	Type       string
	Properties map[string]interface{}
	TrustLevel float64
	Zone       string
	Provider   string
}

// GraphEdge represents an edge between nodes
type GraphEdge struct {
	Source     string
	Target     string
	Weight     float64
	Type       string
	Properties map[string]interface{}
}

// Community represents a detected community in the graph
type Community struct {
	ID       string
	Nodes    []string
	Boundary bool
	Type     string
	Trust    float64
}

// NewBoundaryDetector creates a new trust boundary detector
func NewBoundaryDetector() *BoundaryDetector {
	return &BoundaryDetector{
		nodes: make(map[string]*GraphNode),
		edges: make(map[string][]*GraphEdge),
	}
}

// DetectBoundaries detects trust boundaries in the infrastructure
func (d *BoundaryDetector) DetectBoundaries(model *types.Model, results []*ParseResult) ([]*types.TrustBoundary, error) {
	// Build graph from infrastructure
	d.buildGraph(model, results)
	
	// Apply multiple detection algorithms
	boundaries := []*types.TrustBoundary{}
	
	// 1. Network-based detection
	networkBoundaries := d.detectNetworkBoundaries(results)
	boundaries = append(boundaries, networkBoundaries...)
	
	// 2. IAM-based detection
	iamBoundaries := d.detectIAMBoundaries(results)
	boundaries = append(boundaries, iamBoundaries...)
	
	// 3. Provider-based detection
	providerBoundaries := d.detectProviderBoundaries(results)
	boundaries = append(boundaries, providerBoundaries...)
	
	// 4. Security zone detection
	zoneBoundaries := d.detectSecurityZoneBoundaries(model, results)
	boundaries = append(boundaries, zoneBoundaries...)
	
	// 5. Community-based detection using graph algorithms
	communityBoundaries := d.detectCommunityBoundaries()
	boundaries = append(boundaries, communityBoundaries...)
	
	// 6. Data flow-based detection
	dataFlowBoundaries := d.detectDataFlowBoundaries(model)
	boundaries = append(boundaries, dataFlowBoundaries...)
	
	// 7. Compliance-based boundaries
	complianceBoundaries := d.detectComplianceBoundaries(model, results)
	boundaries = append(boundaries, complianceBoundaries...)
	
	// Merge and deduplicate boundaries
	boundaries = d.mergeBoundaries(boundaries)
	
	// Validate and rank boundaries
	boundaries = d.validateAndRankBoundaries(boundaries, model)
	
	return boundaries, nil
}

// buildGraph builds a graph representation of the infrastructure
func (d *BoundaryDetector) buildGraph(model *types.Model, results []*ParseResult) {
	// Add nodes for technical assets
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
	
	// Add edges for communication links
	for _, link := range model.CommunicationLinks {
		edge := &GraphEdge{
			Source:     link.SourceId,
			Target:     link.TargetId,
			Weight:     d.calculateEdgeWeight(link),
			Type:       string(link.Protocol),
			Properties: d.linkToProperties(link),
		}
		
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

// detectNetworkBoundaries detects boundaries based on network segmentation
func (d *BoundaryDetector) detectNetworkBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	for _, result := range results {
		// VPC boundaries
		for id, network := range result.Networks {
			if network.Type == "vpc" {
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("network-%s", id),
					Title:       fmt.Sprintf("%s Network Boundary", network.Name),
					Description: fmt.Sprintf("Network boundary for %s", network.Name),
					Type:        types.TrustBoundaryType("network-cloud-provider"),
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
		
		// Subnet boundaries
		subnets := d.groupSubnetsByType(result.Networks)
		for subnetType, networks := range subnets {
			if len(networks) > 0 {
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("subnet-group-%s", subnetType),
					Title:       fmt.Sprintf("%s Subnet Group", strings.Title(subnetType)),
					Description: fmt.Sprintf("Subnet grouping for %s networks", subnetType),
					Type:        types.TrustBoundaryType("network-cloud-provider"),
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

// detectIAMBoundaries detects boundaries based on IAM configurations
func (d *BoundaryDetector) detectIAMBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	for _, result := range results {
		// Group resources by IAM roles
		roleGroups := d.groupResourcesByIAMRole(result)
		
		for roleID, resources := range roleGroups {
			if len(resources) > 1 { // Only create boundary if multiple resources share a role
				role := result.Roles[roleID]
				boundary := &types.TrustBoundary{
					Id:          fmt.Sprintf("iam-%s", roleID),
					Title:       fmt.Sprintf("IAM Boundary: %s", role.Name),
					Description: fmt.Sprintf("Resources sharing IAM role %s", role.Name),
					Type:        types.TrustBoundaryType("execution-environment"),
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

// detectProviderBoundaries detects boundaries between different cloud providers
func (d *BoundaryDetector) detectProviderBoundaries(results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Group resources by provider
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
				Type:        types.TrustBoundaryType("network-cloud-provider"),
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

// detectSecurityZoneBoundaries detects boundaries based on security zones
func (d *BoundaryDetector) detectSecurityZoneBoundaries(model *types.Model, results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Define security zones
	zones := map[string]*types.TrustBoundary{
		"public": {
			Id:          "zone-public",
			Title:       "Public Zone",
			Description: "Internet-facing resources",
			Type:        types.TrustBoundaryType("network-on-prem"),
			Tags:        []string{"zone:public", "detection:security-zone"},
		},
		"dmz": {
			Id:          "zone-dmz",
			Title:       "DMZ Zone",
			Description: "Demilitarized zone resources",
			Type:        types.TrustBoundaryType("network-on-prem"),
			Tags:        []string{"zone:dmz", "detection:security-zone"},
		},
		"private": {
			Id:          "zone-private",
			Title:       "Private Zone",
			Description: "Internal resources",
			Type:        types.TrustBoundaryType("network-on-prem"),
			Tags:        []string{"zone:private", "detection:security-zone"},
		},
		"restricted": {
			Id:          "zone-restricted",
			Title:       "Restricted Zone",
			Description: "Highly sensitive resources",
			Type:        types.TrustBoundaryType("network-on-prem"),
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

// detectCommunityBoundaries uses graph algorithms to detect community boundaries
func (d *BoundaryDetector) detectCommunityBoundaries() []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Apply community detection algorithm (simplified Louvain method)
	communities := d.detectCommunities()
	
	for _, community := range communities {
		if community.Boundary {
			boundary := &types.TrustBoundary{
				Id:          fmt.Sprintf("community-%s", community.ID),
				Title:       fmt.Sprintf("Community Boundary %s", community.ID),
				Description: fmt.Sprintf("Detected community of related resources"),
				Type:        types.TrustBoundaryType("execution-environment"),
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

// detectDataFlowBoundaries detects boundaries based on data flow patterns
func (d *BoundaryDetector) detectDataFlowBoundaries(model *types.Model) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Analyze data flow patterns
	dataFlowGroups := d.analyzeDataFlowPatterns(model)
	
	for groupID, assets := range dataFlowGroups {
		if len(assets) > 2 { // Only create boundary for significant groups
			boundary := &types.TrustBoundary{
				Id:          fmt.Sprintf("dataflow-%s", groupID),
				Title:       fmt.Sprintf("Data Flow Boundary %s", groupID),
				Description: "Resources with significant data exchange",
				Type:        types.TrustBoundaryType("execution-environment"),
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

// detectComplianceBoundaries detects boundaries based on compliance requirements
func (d *BoundaryDetector) detectComplianceBoundaries(model *types.Model, results []*ParseResult) []*types.TrustBoundary {
	boundaries := []*types.TrustBoundary{}
	
	// Define compliance boundaries
	complianceZones := map[string]*types.TrustBoundary{
		"pci": {
			Id:          "compliance-pci",
			Title:       "PCI Compliance Boundary",
			Description: "Resources handling payment card data",
			Type:        types.TrustBoundaryType("execution-environment"),
			Tags:        []string{"compliance:pci-dss", "detection:compliance"},
		},
		"hipaa": {
			Id:          "compliance-hipaa",
			Title:       "HIPAA Compliance Boundary",
			Description: "Resources handling protected health information",
			Type:        types.TrustBoundaryType("execution-environment"),
			Tags:        []string{"compliance:hipaa", "detection:compliance"},
		},
		"gdpr": {
			Id:          "compliance-gdpr",
			Title:       "GDPR Compliance Boundary",
			Description: "Resources handling personal data",
			Type:        types.TrustBoundaryType("execution-environment"),
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

// mergeBoundaries merges overlapping boundaries
func (d *BoundaryDetector) mergeBoundaries(boundaries []*types.TrustBoundary) []*types.TrustBoundary {
	merged := []*types.TrustBoundary{}
	processed := make(map[string]bool)
	
	for i, boundary := range boundaries {
		if processed[boundary.Id] {
			continue
		}
		
		// Check for overlapping boundaries
		for j := i + 1; j < len(boundaries); j++ {
			other := boundaries[j]
			if processed[other.Id] {
				continue
			}
			
			overlap := d.calculateOverlap(boundary, other)
			if overlap > 0.8 { // 80% overlap threshold
				// Merge boundaries
				boundary = d.mergeTwoBoundaries(boundary, other)
				processed[other.Id] = true
			}
		}
		
		merged = append(merged, boundary)
		processed[boundary.Id] = true
	}
	
	return merged
}

// validateAndRankBoundaries validates and ranks boundaries by importance
func (d *BoundaryDetector) validateAndRankBoundaries(boundaries []*types.TrustBoundary, model *types.Model) []*types.TrustBoundary {
	// Calculate scores for each boundary
	type scoredBoundary struct {
		boundary *types.TrustBoundary
		score    float64
	}
	
	scored := []scoredBoundary{}
	
	for _, boundary := range boundaries {
		score := d.calculateBoundaryScore(boundary, model)
		if score > 0.3 { // Minimum score threshold
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
	case "external-entity":
		trust = 0.1
	case "process":
		trust = 0.6
	case "datastore":
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
	if asset.Type == "external-entity" {
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
	if link.Protocol == "https" || link.Protocol == "tls" {
		weight += 0.2
	}
	
	// Adjust based on authentication
	if link.Authentication != "none" {
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
	if asset.Type == "external-entity" {
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
			if dataAsset.Confidentiality == "strictly-confidential" {
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
	case "network-cloud-provider":
		score += 0.8
	case "execution-environment":
		score += 0.6
	case "network-on-prem":
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
			if asset.Type == "datastore" || strings.Contains(strings.ToLower(asset.Title), "database") {
				criticalAssets++
			}
		}
	}
	score += float64(criticalAssets) * 0.2
	
	// Normalize score
	return math.Min(score/3.0, 1.0)
}