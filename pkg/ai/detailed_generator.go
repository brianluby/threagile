package ai

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// DetailedGenerator implements detailed threat model generation from IaC
type DetailedGenerator struct {
	simpleGen *SimpleGenerator
}

// NewDetailedGenerator creates a new detailed generator
func NewDetailedGenerator() *DetailedGenerator {
	return &DetailedGenerator{
		simpleGen: NewSimpleGenerator(),
	}
}

// Generate creates a detailed threat model from parsed infrastructure
func (g *DetailedGenerator) Generate(results []*ParseResult, options GeneratorOptions) (*types.Model, error) {
	// First, use simple generator as a base
	model, err := g.simpleGen.Generate(results, options)
	if err != nil {
		return nil, fmt.Errorf("base generation failed: %w", err)
	}

	// Enhance with detailed analysis
	for _, result := range results {
		// Add detailed security configurations
		g.enhanceSecurityConfigurations(model, result)
		
		// Add detailed network segmentation
		g.enhanceNetworkSegmentation(model, result)
		
		// Add detailed IAM analysis
		g.enhanceIAMAnalysis(model, result)
		
		// Add detailed data flow analysis
		g.enhanceDataFlows(model, result)
		
		// Add detailed compliance mappings
		g.enhanceComplianceMappings(model, result)
		
		// Add detailed encryption analysis
		g.enhanceEncryptionAnalysis(model, result)
	}

	// Perform cross-resource analysis
	g.performCrossResourceAnalysis(model, results)
	
	// Generate detailed risk tracking
	g.generateDetailedRiskTracking(model)
	
	// Add detailed metadata
	g.addDetailedMetadata(model, results)

	return model, nil
}

// enhanceSecurityConfigurations adds detailed security configuration analysis
func (g *DetailedGenerator) enhanceSecurityConfigurations(model *types.Model, result *ParseResult) {
	// Analyze security groups in detail
	for _, sg := range result.SecurityGroups {
		// Check for overly permissive rules
		for _, rule := range sg.Rules {
			if g.isOverlyPermissive(rule) {
				// Add risk tracking for overly permissive rules
				g.addSecurityRisk(model, sg.ID, "overly-permissive", rule)
			}
			
			// Check for missing egress rules
			if !g.hasEgressRules(sg) {
				g.addSecurityRisk(model, sg.ID, "missing-egress-rules", nil)
			}
		}
		
		// Enhance technical assets with security group details
		for id, asset := range model.TechnicalAssets {
			if g.assetUsesSecurityGroup(asset, sg) {
				g.enhanceAssetSecurity(asset, sg)
			}
		}
	}
}

// enhanceNetworkSegmentation adds detailed network segmentation analysis
func (g *DetailedGenerator) enhanceNetworkSegmentation(model *types.Model, result *ParseResult) {
	// Analyze network configurations
	for _, network := range result.Networks {
		// Determine network zone
		zone := g.determineNetworkZone(network)
		
		// Create or update trust boundary for the network
		boundaryID := fmt.Sprintf("network-%s", network.ID)
		if boundary, exists := model.TrustBoundaries[boundaryID]; exists {
			// Enhance existing boundary
			g.enhanceTrustBoundary(boundary, network, zone)
		} else {
			// Create new trust boundary
			model.TrustBoundaries[boundaryID] = g.createNetworkBoundary(network, zone)
		}
		
		// Map assets to network zones
		g.mapAssetsToNetworkZones(model, network, zone)
	}
}

// enhanceIAMAnalysis adds detailed IAM configuration analysis
func (g *DetailedGenerator) enhanceIAMAnalysis(model *types.Model, result *ParseResult) {
	// Analyze IAM roles
	for _, role := range result.Roles {
		// Check for excessive permissions
		if g.hasExcessivePermissions(role) {
			g.addIAMRisk(model, role.ID, "excessive-permissions")
		}
		
		// Check for cross-account access
		if g.allowsCrossAccountAccess(role) {
			g.addIAMRisk(model, role.ID, "cross-account-access")
		}
	}
	
	// Analyze IAM policies
	for _, policy := range result.Policies {
		// Check for wildcards in policies
		if g.hasWildcardPermissions(policy) {
			g.addIAMRisk(model, policy.ID, "wildcard-permissions")
		}
		
		// Check for admin privileges
		if g.hasAdminPrivileges(policy) {
			g.addIAMRisk(model, policy.ID, "admin-privileges")
		}
	}
	
	// Map IAM configurations to technical assets
	g.mapIAMToAssets(model, result)
}

// enhanceDataFlows adds detailed data flow analysis
func (g *DetailedGenerator) enhanceDataFlows(model *types.Model, result *ParseResult) {
	// Analyze data stores
	for _, db := range result.Databases {
		// Determine data classification
		classification := g.determineDataClassification(db)
		
		// Create data asset if not exists
		dataAssetID := fmt.Sprintf("data-%s", db.ID)
		if _, exists := model.DataAssets[dataAssetID]; !exists {
			model.DataAssets[dataAssetID] = g.createDataAsset(db, classification)
		}
		
		// Analyze data flows to/from database
		g.analyzeDataFlows(model, db, classification)
	}
	
	// Analyze storage
	for _, storage := range result.Storages {
		// Check for public access
		if g.hasPublicAccess(storage) {
			g.addStorageRisk(model, storage.ID, "public-access")
		}
		
		// Check for encryption
		if !g.isEncrypted(storage) {
			g.addStorageRisk(model, storage.ID, "unencrypted-storage")
		}
	}
}

// enhanceComplianceMappings adds compliance requirement mappings
func (g *DetailedGenerator) enhanceComplianceMappings(model *types.Model, result *ParseResult) {
	// Add compliance tags based on detected patterns
	compliancePatterns := g.detectCompliancePatterns(result)
	
	for pattern, assets := range compliancePatterns {
		for _, assetID := range assets {
			if asset, exists := model.TechnicalAssets[assetID]; exists {
				// Add compliance tag
				complianceTag := fmt.Sprintf("compliance:%s", pattern)
				if !g.hasTag(asset, complianceTag) {
					asset.Tags = append(asset.Tags, complianceTag)
				}
			}
		}
	}
}

// enhanceEncryptionAnalysis adds detailed encryption analysis
func (g *DetailedGenerator) enhanceEncryptionAnalysis(model *types.Model, result *ParseResult) {
	// Check encryption in transit
	for id, link := range model.CommunicationLinks {
		if !g.isEncryptedInTransit(link) {
			g.addCommunicationRisk(model, id, "unencrypted-transit")
		}
	}
	
	// Check encryption at rest
	for id, asset := range model.TechnicalAssets {
		if g.storesData(asset) && !g.hasEncryptionAtRest(asset) {
			g.addEncryptionRisk(model, id, "unencrypted-at-rest")
		}
	}
}

// performCrossResourceAnalysis performs analysis across multiple resources
func (g *DetailedGenerator) performCrossResourceAnalysis(model *types.Model, results []*ParseResult) {
	// Analyze resource dependencies
	dependencies := g.analyzeDependencies(results)
	
	// Identify single points of failure
	spofs := g.identifySPOFs(dependencies)
	for _, spof := range spofs {
		g.addArchitectureRisk(model, spof, "single-point-of-failure")
	}
	
	// Identify missing redundancy
	missingRedundancy := g.identifyMissingRedundancy(model)
	for _, assetID := range missingRedundancy {
		g.addArchitectureRisk(model, assetID, "missing-redundancy")
	}
	
	// Analyze attack paths
	attackPaths := g.analyzeAttackPaths(model)
	for _, path := range attackPaths {
		g.addAttackPathRisk(model, path)
	}
}

// generateDetailedRiskTracking generates detailed risk tracking entries
func (g *DetailedGenerator) generateDetailedRiskTracking(model *types.Model) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	// Add risk tracking for identified issues
	for id, asset := range model.TechnicalAssets {
		risks := g.identifyAssetRisks(asset)
		for _, risk := range risks {
			trackingID := fmt.Sprintf("%s-%s", id, risk.Type)
			model.RiskTracking[trackingID] = &types.RiskTracking{
				Status:         "unchecked",
				Justification:  fmt.Sprintf("Automatically identified %s risk for %s", risk.Type, asset.Title),
				Ticket:         "",
				Date:           "",
				CheckedBy:      "",
			}
		}
	}
}

// addDetailedMetadata adds detailed metadata to the model
func (g *DetailedGenerator) addDetailedMetadata(model *types.Model, results []*ParseResult) {
	// Count resources by type
	resourceCounts := make(map[string]int)
	for _, result := range results {
		resourceCounts["resources"] += len(result.Resources)
		resourceCounts["databases"] += len(result.Databases)
		resourceCounts["networks"] += len(result.Networks)
		resourceCounts["security_groups"] += len(result.SecurityGroups)
		resourceCounts["storages"] += len(result.Storages)
		resourceCounts["functions"] += len(result.Functions)
		resourceCounts["containers"] += len(result.Containers)
	}
	
	// Add to model metadata
	if model.Overview == nil {
		model.Overview = &types.Overview{}
	}
	
	if model.Overview.Description == "" {
		model.Overview.Description = "Threat model generated from Infrastructure as Code with detailed analysis"
	}
	
	// Add business criticality based on resources
	if model.Overview.BusinessCriticality == "" {
		model.Overview.BusinessCriticality = g.determineBusinessCriticality(resourceCounts)
	}
}

// Helper methods for detailed analysis

func (g *DetailedGenerator) isOverlyPermissive(rule SecurityRule) bool {
	// Check if rule allows access from anywhere
	return rule.Source == "0.0.0.0/0" || rule.Source == "::/0"
}

func (g *DetailedGenerator) hasEgressRules(sg *SecurityGroup) bool {
	for _, rule := range sg.Rules {
		if rule.Direction == "egress" {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) assetUsesSecurityGroup(asset *types.TechnicalAsset, sg *SecurityGroup) bool {
	// Check if asset references this security group
	for _, tag := range asset.Tags {
		if strings.Contains(tag, sg.ID) {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) enhanceAssetSecurity(asset *types.TechnicalAsset, sg *SecurityGroup) {
	// Add security group details to asset
	sgTag := fmt.Sprintf("security-group:%s", sg.Name)
	if !g.hasTag(asset, sgTag) {
		asset.Tags = append(asset.Tags, sgTag)
	}
}

func (g *DetailedGenerator) determineNetworkZone(network *Network) string {
	// Determine if network is public, private, or DMZ
	if strings.Contains(strings.ToLower(network.Name), "public") {
		return "public"
	}
	if strings.Contains(strings.ToLower(network.Name), "dmz") {
		return "dmz"
	}
	return "private"
}

func (g *DetailedGenerator) enhanceTrustBoundary(boundary *types.TrustBoundary, network *Network, zone string) {
	// Enhance trust boundary with network details
	boundary.Tags = append(boundary.Tags, fmt.Sprintf("zone:%s", zone))
	boundary.Tags = append(boundary.Tags, fmt.Sprintf("network:%s", network.Type))
}

func (g *DetailedGenerator) createNetworkBoundary(network *Network, zone string) *types.TrustBoundary {
	return &types.TrustBoundary{
		Id:          fmt.Sprintf("network-%s", network.ID),
		Title:       fmt.Sprintf("%s Network", network.Name),
		Description: fmt.Sprintf("Network boundary for %s zone", zone),
		Type:        types.TrustBoundaryType("network-cloud-provider"),
		Tags: []string{
			fmt.Sprintf("zone:%s", zone),
			fmt.Sprintf("network:%s", network.Type),
			fmt.Sprintf("provider:%s", network.Provider),
		},
	}
}

func (g *DetailedGenerator) mapAssetsToNetworkZones(model *types.Model, network *Network, zone string) {
	// Map technical assets to their network zones
	for _, asset := range model.TechnicalAssets {
		if g.assetInNetwork(asset, network) {
			zoneTag := fmt.Sprintf("network-zone:%s", zone)
			if !g.hasTag(asset, zoneTag) {
				asset.Tags = append(asset.Tags, zoneTag)
			}
		}
	}
}

func (g *DetailedGenerator) hasExcessivePermissions(role *Role) bool {
	// Check for * permissions or admin access
	return strings.Contains(role.Description, "*") || 
		   strings.Contains(strings.ToLower(role.Name), "admin")
}

func (g *DetailedGenerator) allowsCrossAccountAccess(role *Role) bool {
	// Check for cross-account trust relationships
	return strings.Contains(role.Description, "cross-account") ||
		   strings.Contains(role.Description, "external")
}

func (g *DetailedGenerator) hasWildcardPermissions(policy *Policy) bool {
	// Check for wildcard permissions in policy
	return strings.Contains(policy.Description, "*")
}

func (g *DetailedGenerator) hasAdminPrivileges(policy *Policy) bool {
	// Check for admin privileges
	return strings.Contains(strings.ToLower(policy.Name), "admin") ||
		   strings.Contains(strings.ToLower(policy.Description), "admin")
}

func (g *DetailedGenerator) mapIAMToAssets(model *types.Model, result *ParseResult) {
	// Map IAM roles and policies to technical assets
	for _, asset := range model.TechnicalAssets {
		// Add IAM tags to assets
		for _, role := range result.Roles {
			if g.roleAppliesToAsset(role, asset) {
				roleTag := fmt.Sprintf("iam-role:%s", role.Name)
				if !g.hasTag(asset, roleTag) {
					asset.Tags = append(asset.Tags, roleTag)
				}
			}
		}
	}
}

func (g *DetailedGenerator) determineDataClassification(db *Database) string {
	// Determine data classification based on database name and type
	name := strings.ToLower(db.Name)
	if strings.Contains(name, "user") || strings.Contains(name, "customer") {
		return "confidential"
	}
	if strings.Contains(name, "payment") || strings.Contains(name, "credit") {
		return "restricted"
	}
	if strings.Contains(name, "public") || strings.Contains(name, "cache") {
		return "public"
	}
	return "internal"
}

func (g *DetailedGenerator) createDataAsset(db *Database, classification string) *types.DataAsset {
	return &types.DataAsset{
		Id:    fmt.Sprintf("data-%s", db.ID),
		Title: fmt.Sprintf("%s Data", db.Name),
		Description: fmt.Sprintf("Data stored in %s database", db.Name),
		Usage: types.UsageType("business"),
		Tags: []string{
			fmt.Sprintf("classification:%s", classification),
			fmt.Sprintf("database:%s", db.Type),
		},
		Origin:             "IaC",
		Owner:              "system",
		Quantity:           types.Quantity("many"),
		Confidentiality:    g.mapToConfidentiality(classification),
		Integrity:          g.mapToIntegrity(classification),
		Availability:       g.mapToAvailability(classification),
	}
}

func (g *DetailedGenerator) analyzeDataFlows(model *types.Model, db *Database, classification string) {
	// Analyze data flows between database and other components
	for _, asset := range model.TechnicalAssets {
		if g.assetAccessesDatabase(asset, db) {
			// Create communication link if not exists
			linkID := fmt.Sprintf("%s-to-%s", asset.Id, db.ID)
			if _, exists := model.CommunicationLinks[linkID]; !exists {
				model.CommunicationLinks[linkID] = g.createDataFlow(asset.Id, db.ID, classification)
			}
		}
	}
}

func (g *DetailedGenerator) hasPublicAccess(storage *Storage) bool {
	// Check if storage has public access
	for k, v := range storage.Tags {
		if strings.ToLower(k) == "public" && v == "true" {
			return true
		}
	}
	return strings.Contains(strings.ToLower(storage.Name), "public")
}

func (g *DetailedGenerator) isEncrypted(storage *Storage) bool {
	// Check if storage is encrypted
	for k, v := range storage.Tags {
		if strings.Contains(strings.ToLower(k), "encrypt") && v == "true" {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) detectCompliancePatterns(result *ParseResult) map[string][]string {
	patterns := make(map[string][]string)
	
	// Check for PCI compliance patterns
	if g.hasPCIPatterns(result) {
		patterns["pci-dss"] = g.getPCIAssets(result)
	}
	
	// Check for HIPAA compliance patterns
	if g.hasHIPAAPatterns(result) {
		patterns["hipaa"] = g.getHIPAAAssets(result)
	}
	
	// Check for GDPR compliance patterns
	if g.hasGDPRPatterns(result) {
		patterns["gdpr"] = g.getGDPRAssets(result)
	}
	
	return patterns
}

func (g *DetailedGenerator) hasTag(asset *types.TechnicalAsset, tag string) bool {
	for _, t := range asset.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) isEncryptedInTransit(link *types.CommunicationLink) bool {
	// Check if communication uses encrypted protocols
	protocol := strings.ToLower(string(link.Protocol))
	return strings.Contains(protocol, "https") || 
		   strings.Contains(protocol, "tls") ||
		   strings.Contains(protocol, "ssh")
}

func (g *DetailedGenerator) storesData(asset *types.TechnicalAsset) bool {
	// Check if asset stores data
	return asset.Type == "datastore" || 
		   strings.Contains(strings.ToLower(asset.Title), "database") ||
		   strings.Contains(strings.ToLower(asset.Title), "storage")
}

func (g *DetailedGenerator) hasEncryptionAtRest(asset *types.TechnicalAsset) bool {
	// Check if asset has encryption at rest
	for _, tag := range asset.Tags {
		if strings.Contains(strings.ToLower(tag), "encrypted") {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) analyzeDependencies(results []*ParseResult) map[string][]string {
	dependencies := make(map[string][]string)
	// Analyze dependencies between resources
	// This would be implemented based on IaC-specific patterns
	return dependencies
}

func (g *DetailedGenerator) identifySPOFs(dependencies map[string][]string) []string {
	spofs := []string{}
	// Identify single points of failure from dependency graph
	for resource, deps := range dependencies {
		if len(deps) > 3 { // If more than 3 resources depend on this
			spofs = append(spofs, resource)
		}
	}
	return spofs
}

func (g *DetailedGenerator) identifyMissingRedundancy(model *types.Model) []string {
	missing := []string{}
	// Identify critical assets without redundancy
	for id, asset := range model.TechnicalAssets {
		if g.isCritical(asset) && !g.hasRedundancy(asset, model) {
			missing = append(missing, id)
		}
	}
	return missing
}

func (g *DetailedGenerator) analyzeAttackPaths(model *types.Model) [][]string {
	paths := [][]string{}
	// Analyze potential attack paths through the infrastructure
	// This would use graph algorithms to find paths from external to critical assets
	return paths
}

func (g *DetailedGenerator) identifyAssetRisks(asset *types.TechnicalAsset) []struct{ Type string } {
	risks := []struct{ Type string }{}
	// Identify risks specific to this asset
	if !g.hasEncryptionAtRest(asset) && g.storesData(asset) {
		risks = append(risks, struct{ Type string }{"missing-encryption"})
	}
	return risks
}

func (g *DetailedGenerator) determineBusinessCriticality(counts map[string]int) string {
	// Determine business criticality based on resource counts
	totalResources := 0
	for _, count := range counts {
		totalResources += count
	}
	
	if totalResources > 50 || counts["databases"] > 5 {
		return "critical"
	}
	if totalResources > 20 || counts["databases"] > 2 {
		return "important"
	}
	return "internal"
}

// Risk tracking helper methods

func (g *DetailedGenerator) addSecurityRisk(model *types.Model, assetID, riskType string, rule interface{}) {
	// Add security risk to model
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("security-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Security risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addIAMRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("iam-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("IAM risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addStorageRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("storage-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Storage risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addCommunicationRisk(model *types.Model, linkID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("comm-%s-%s", linkID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Communication risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addEncryptionRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("encryption-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Encryption risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addArchitectureRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("arch-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Architecture risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addAttackPathRisk(model *types.Model, path []string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	pathStr := strings.Join(path, "->")
	riskID := fmt.Sprintf("attack-path-%s", pathStr)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        "unchecked",
		Justification: fmt.Sprintf("Potential attack path: %s", pathStr),
	}
}

// Additional helper methods

func (g *DetailedGenerator) assetInNetwork(asset *types.TechnicalAsset, network *Network) bool {
	// Check if asset is in the network
	// This would be based on tags or other metadata
	return false // Placeholder
}

func (g *DetailedGenerator) roleAppliesToAsset(role *Role, asset *types.TechnicalAsset) bool {
	// Check if IAM role applies to this asset
	return false // Placeholder
}

func (g *DetailedGenerator) mapToConfidentiality(classification string) types.Confidentiality {
	switch classification {
	case "restricted":
		return types.Confidentiality("strictly-confidential")
	case "confidential":
		return types.Confidentiality("confidential")
	case "internal":
		return types.Confidentiality("internal")
	default:
		return types.Confidentiality("public")
	}
}

func (g *DetailedGenerator) mapToIntegrity(classification string) types.Criticality {
	switch classification {
	case "restricted", "confidential":
		return types.Criticality("critical")
	case "internal":
		return types.Criticality("important")
	default:
		return types.Criticality("operational")
	}
}

func (g *DetailedGenerator) mapToAvailability(classification string) types.Criticality {
	switch classification {
	case "restricted":
		return types.Criticality("critical")
	case "confidential", "internal":
		return types.Criticality("important")
	default:
		return types.Criticality("operational")
	}
}

func (g *DetailedGenerator) assetAccessesDatabase(asset *types.TechnicalAsset, db *Database) bool {
	// Check if asset accesses the database
	// This would be based on connectivity analysis
	return false // Placeholder
}

func (g *DetailedGenerator) createDataFlow(sourceID, targetID, classification string) *types.CommunicationLink {
	return &types.CommunicationLink{
		SourceId: sourceID,
		TargetId: targetID,
		Title:    fmt.Sprintf("Data flow to %s", targetID),
		Description: fmt.Sprintf("Data flow for %s data", classification),
		Protocol: types.Protocol("https"),
		Authentication: types.Authentication("credentials"),
		Authorization: types.Authorization("technical-user"),
		Usage: types.Usage("business"),
	}
}

func (g *DetailedGenerator) hasPCIPatterns(result *ParseResult) bool {
	// Check for PCI compliance patterns
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "payment") ||
		   strings.Contains(strings.ToLower(db.Name), "card") {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) getPCIAssets(result *ParseResult) []string {
	assets := []string{}
	// Get assets related to PCI compliance
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "payment") ||
		   strings.Contains(strings.ToLower(db.Name), "card") {
			assets = append(assets, db.ID)
		}
	}
	return assets
}

func (g *DetailedGenerator) hasHIPAAPatterns(result *ParseResult) bool {
	// Check for HIPAA compliance patterns
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "patient") ||
		   strings.Contains(strings.ToLower(db.Name), "medical") ||
		   strings.Contains(strings.ToLower(db.Name), "health") {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) getHIPAAAssets(result *ParseResult) []string {
	assets := []string{}
	// Get assets related to HIPAA compliance
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "patient") ||
		   strings.Contains(strings.ToLower(db.Name), "medical") ||
		   strings.Contains(strings.ToLower(db.Name), "health") {
			assets = append(assets, db.ID)
		}
	}
	return assets
}

func (g *DetailedGenerator) hasGDPRPatterns(result *ParseResult) bool {
	// Check for GDPR compliance patterns
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "user") ||
		   strings.Contains(strings.ToLower(db.Name), "customer") ||
		   strings.Contains(strings.ToLower(db.Name), "personal") {
			return true
		}
	}
	return false
}

func (g *DetailedGenerator) getGDPRAssets(result *ParseResult) []string {
	assets := []string{}
	// Get assets related to GDPR compliance
	for _, db := range result.Databases {
		if strings.Contains(strings.ToLower(db.Name), "user") ||
		   strings.Contains(strings.ToLower(db.Name), "customer") ||
		   strings.Contains(strings.ToLower(db.Name), "personal") {
			assets = append(assets, db.ID)
		}
	}
	return assets
}

func (g *DetailedGenerator) isCritical(asset *types.TechnicalAsset) bool {
	// Check if asset is critical
	return asset.Type == "datastore" || 
		   strings.Contains(strings.ToLower(asset.Title), "database") ||
		   strings.Contains(strings.ToLower(asset.Title), "payment")
}

func (g *DetailedGenerator) hasRedundancy(asset *types.TechnicalAsset, model *types.Model) bool {
	// Check if asset has redundancy
	// Look for similar assets or load balancers
	count := 0
	for _, other := range model.TechnicalAssets {
		if other.Type == asset.Type && strings.Contains(other.Title, asset.Title) {
			count++
		}
	}
	return count > 1
}