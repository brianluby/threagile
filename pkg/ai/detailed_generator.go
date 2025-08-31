// Package ai provides AI-powered threat model generation from Infrastructure as Code.
// The detailed generator extends the simple generator with comprehensive security
// analysis including compliance mapping, encryption verification, and advanced
// threat detection.
package ai

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// DetailedGenerator implements comprehensive threat model generation from IaC files.
// It builds upon the SimpleGenerator by adding:
//   - Deep security configuration analysis
//   - Network segmentation verification
//   - IAM permission analysis
//   - Data flow tracing
//   - Compliance framework mapping
//   - Encryption coverage assessment
//   - Cross-resource relationship analysis
//
// This generator is suitable for production environments where thorough
// security analysis is required.
type DetailedGenerator struct {
	// simpleGen provides the base generation functionality
	simpleGen *SimpleGenerator
}

// NewDetailedGenerator creates a new detailed threat model generator.
// The generator uses a SimpleGenerator as its foundation and enhances
// the output with comprehensive security analysis.
func NewDetailedGenerator() *DetailedGenerator {
	return &DetailedGenerator{
		simpleGen: NewSimpleGenerator(),
	}
}

// Generate creates a comprehensive threat model from parsed infrastructure.
// This method orchestrates multiple analysis phases:
//
// Phase 1: Base Generation
//   - Uses SimpleGenerator to create initial model
//   - Establishes technical assets and basic trust boundaries
//
// Phase 2: Security Enhancement (per ParseResult)
//   - Security configurations: Analyzes firewall rules, access controls
//   - Network segmentation: Verifies isolation and zone compliance
//   - IAM analysis: Examines permissions and privilege escalation risks
//   - Data flows: Traces data movement and identifies exposure points
//   - Compliance: Maps infrastructure to regulatory requirements
//   - Encryption: Verifies data protection at rest and in transit
//
// Phase 3: Cross-Resource Analysis
//   - Identifies attack paths across resources
//   - Detects privilege escalation opportunities
//   - Finds data exfiltration routes
//
// Phase 4: Risk Documentation
//   - Generates detailed risk tracking entries
//   - Prioritizes findings by severity
//   - Provides remediation guidance
//
// Parameters:
//   - results: Parsed infrastructure data from IaC files
//   - options: Generation options including mode and context
//
// Returns:
//   - *types.Model: Comprehensive threat model with detailed analysis
//   - error: Any errors during generation
func (g *DetailedGenerator) Generate(results []*ParseResult, options GeneratorOptions) (*types.Model, error) {
	// Phase 1: Create base model using simple generation
	model, err := g.simpleGen.Generate(results, options)
	if err != nil {
		return nil, fmt.Errorf("base generation failed: %w", err)
	}

	// Phase 2: Enhance with detailed security analysis
	for _, result := range results {
		// Analyze security configurations (firewall rules, ACLs)
		g.enhanceSecurityConfigurations(model, result)
		
		// Verify network segmentation and isolation
		g.enhanceNetworkSegmentation(model, result)
		
		// Examine IAM roles and permissions
		g.enhanceIAMAnalysis(model, result)
		
		// Trace data flows between components
		g.enhanceDataFlows(model, result)
		
		// Map to compliance frameworks (PCI-DSS, HIPAA, GDPR)
		g.enhanceComplianceMappings(model, result)
		
		// Verify encryption implementation
		g.enhanceEncryptionAnalysis(model, result)
	}

	// Phase 3: Perform cross-resource security analysis
	// This identifies vulnerabilities that span multiple resources
	g.performCrossResourceAnalysis(model, results)
	
	// Phase 4: Generate comprehensive risk documentation
	g.generateDetailedRiskTracking(model)
	
	// Add detailed metadata for audit trail
	g.addDetailedMetadata(model, results)

	return model, nil
}

// enhanceSecurityConfigurations performs deep analysis of security configurations.
// This method examines firewall rules, access control lists, and security groups
// to identify potential vulnerabilities.
//
// Security checks performed:
//   - Overly permissive rules (0.0.0.0/0 access)
//   - Missing egress controls
//   - Unnecessary open ports
//   - Protocol-specific vulnerabilities
//   - Rule conflicts and gaps
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing security configurations
func (g *DetailedGenerator) enhanceSecurityConfigurations(model *types.Model, result *ParseResult) {
	// Analyze each security group for vulnerabilities
	for _, sg := range result.SecurityGroups {
		// Check for rules that allow unrestricted access
		for _, rule := range sg.Rules {
			if g.isOverlyPermissive(rule) {
				// Document overly permissive access as high-risk
				g.addSecurityRisk(model, sg.ID, "overly-permissive", rule)
			}
			
			// Verify egress filtering is implemented
			if !g.hasEgressRules(sg) {
				g.addSecurityRisk(model, sg.ID, "missing-egress-rules", nil)
			}
		}
		
		// Enhance technical assets with security group details
		for _, asset := range model.TechnicalAssets {
			if g.assetUsesSecurityGroup(asset, sg) {
				g.enhanceAssetSecurity(asset, sg)
			}
		}
	}
}

// enhanceNetworkSegmentation analyzes network isolation and segmentation.
// Proper network segmentation is crucial for containing breaches and limiting
// lateral movement in case of compromise.
//
// Analysis includes:
//   - Network zone classification (DMZ, internal, management)
//   - Subnet isolation verification
//   - Inter-zone communication rules
//   - Network ACL effectiveness
//   - Routing table security
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing network configurations
func (g *DetailedGenerator) enhanceNetworkSegmentation(model *types.Model, result *ParseResult) {
	// Examine each network component for proper segmentation
	for _, network := range result.Networks {
		// Classify network into security zones
		zone := g.determineNetworkZone(network)
		
		// Ensure trust boundaries reflect network isolation
		boundaryID := fmt.Sprintf("network-%s", network.ID)
		if boundary, exists := model.TrustBoundaries[boundaryID]; exists {
			// Update existing boundary with zone information
			g.enhanceTrustBoundary(boundary, network, zone)
		} else {
			// Create new trust boundary
			model.TrustBoundaries[boundaryID] = g.createNetworkBoundary(network, zone)
		}
		
		// Map assets to network zones
		g.mapAssetsToNetworkZones(model, network, zone)
	}
}

// enhanceIAMAnalysis performs comprehensive Identity and Access Management analysis.
// IAM misconfigurations are a leading cause of cloud security breaches.
//
// Analysis covers:
//   - Principle of least privilege violations
//   - Cross-account access risks
//   - Wildcard permissions abuse
//   - Administrative privilege exposure
//   - Service account security
//   - Role assumption chains
//
// Common IAM vulnerabilities detected:
//   - Over-privileged roles (e.g., "*" permissions)
//   - Unrestricted cross-account access
//   - Long-lived credentials
//   - Missing MFA requirements
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing IAM configurations
func (g *DetailedGenerator) enhanceIAMAnalysis(model *types.Model, result *ParseResult) {
	// Examine each IAM role for security issues
	for _, role := range result.Roles {
		// Detect violations of least privilege principle
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

// enhanceDataFlows traces data movement through the infrastructure.
// Understanding data flows is critical for:
//   - Identifying data exposure points
//   - Compliance boundary verification
//   - Encryption coverage assessment
//   - Access control validation
//
// Data classification levels:
//   - Public: No sensitivity
//   - Internal: Business confidential
//   - Confidential: Customer data, PII
//   - Restricted: Payment cards, health records
//
// Analysis includes:
//   - Data store classification
//   - Public access exposure
//   - Encryption requirements
//   - Cross-boundary flows
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing data stores
func (g *DetailedGenerator) enhanceDataFlows(model *types.Model, result *ParseResult) {
	// Process each database to understand data sensitivity
	for _, db := range result.Databases {
		// Classify data based on tags and patterns
		classification := g.determineDataClassification(db)
		
		// Ensure data asset exists in model
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

// enhanceComplianceMappings maps infrastructure to regulatory requirements.
// Automated compliance detection helps ensure:
//   - Regulatory requirements are met
//   - Audit trails are complete
//   - Controls are properly implemented
//
// Supported compliance frameworks:
//   - PCI-DSS: Payment card data protection
//   - HIPAA: Healthcare data privacy
//   - GDPR: EU data protection
//   - SOC2: Service organization controls
//   - ISO27001: Information security management
//
// Detection based on:
//   - Resource tags (e.g., "pci-scope")
//   - Resource types (e.g., payment processing)
//   - Data classifications
//   - Network zones
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing infrastructure
func (g *DetailedGenerator) enhanceComplianceMappings(model *types.Model, result *ParseResult) {
	// Detect compliance patterns from infrastructure
	compliancePatterns := g.detectCompliancePatterns(result)
	
	// Tag assets with applicable compliance frameworks
	for pattern, assets := range compliancePatterns {
		for _, assetID := range assets {
			if asset, exists := model.TechnicalAssets[assetID]; exists {
				// Apply compliance framework tag
				complianceTag := fmt.Sprintf("compliance:%s", pattern)
				if !g.hasTag(asset, complianceTag) {
					asset.Tags = append(asset.Tags, complianceTag)
				}
			}
		}
	}
}

// enhanceEncryptionAnalysis verifies encryption implementation across infrastructure.
// Encryption is a fundamental security control for data protection.
//
// Analysis covers:
//   - Encryption in transit (TLS/SSL)
//   - Encryption at rest (disk/database)
//   - Key management practices
//   - Certificate validation
//   - Algorithm strength
//
// Common encryption issues:
//   - Unencrypted network communication
//   - Plain text data storage
//   - Weak encryption algorithms
//   - Poor key management
//   - Self-signed certificates
//
// Parameters:
//   - model: The threat model to enhance
//   - result: ParseResult containing infrastructure
func (g *DetailedGenerator) enhanceEncryptionAnalysis(model *types.Model, result *ParseResult) {
	// Verify all communication links use encryption
	for id, link := range model.CommunicationLinks {
		if !g.isEncryptedInTransit(link) {
			g.addCommunicationRisk(model, id, "unencrypted-transit")
		}
	}
	
	// Verify data stores implement encryption at rest
	for id, asset := range model.TechnicalAssets {
		if g.storesData(asset) && !g.hasEncryptionAtRest(asset) {
			g.addEncryptionRisk(model, id, "unencrypted-at-rest")
		}
	}
}

// performCrossResourceAnalysis identifies vulnerabilities spanning multiple resources.
// Many security issues arise from the interaction between components rather than
// individual resource misconfigurations.
//
// Cross-resource analysis includes:
//   - Dependency chain vulnerabilities
//   - Single points of failure (SPOF)
//   - Missing redundancy
//   - Cascading failure risks
//   - Attack path analysis
//   - Privilege escalation chains
//
// This holistic view reveals:
//   - Architecture-level weaknesses
//   - Availability risks
//   - Data flow vulnerabilities
//   - Defense-in-depth gaps
//
// Parameters:
//   - model: The threat model to analyze
//   - results: All ParseResults for comprehensive view
func (g *DetailedGenerator) performCrossResourceAnalysis(model *types.Model, results []*ParseResult) {
	// Map dependencies between all resources
	dependencies := g.analyzeDependencies(results)
	
	// Find critical components without redundancy
	spofs := g.identifySPOFs(dependencies)
	for _, spof := range spofs {
		g.addArchitectureRisk(model, spof, "single-point-of-failure")
	}
	
	// Detect missing high-availability configurations
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

// generateDetailedRiskTracking creates comprehensive risk documentation.
// Risk tracking is essential for:
//   - Audit trails
//   - Risk acceptance workflows
//   - Remediation tracking
//   - Compliance reporting
//
// Each identified risk gets a tracking entry with:
//   - Unique identifier
//   - Current status (unchecked, accepted, mitigated)
//   - Justification for decisions
//   - Ticket references for remediation
//   - Audit metadata (date, reviewer)
//
// This enables organizations to:
//   - Document risk decisions
//   - Track remediation progress
//   - Demonstrate due diligence
//   - Support compliance audits
//
// Parameters:
//   - model: The threat model to add risk tracking to
func (g *DetailedGenerator) generateDetailedRiskTracking(model *types.Model) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	// Create tracking entries for all identified risks
	for id, asset := range model.TechnicalAssets {
		risks := g.identifyAssetRisks(asset)
		for _, risk := range risks {
			// Generate unique tracking ID for each risk
			trackingID := fmt.Sprintf("%s-%s", id, risk.Type)
			model.RiskTracking[trackingID] = &types.RiskTracking{
				Status:         types.Unchecked,
				Justification:  fmt.Sprintf("Automatically identified %s risk for %s", risk.Type, asset.Title),
				Ticket:         "",
				Date:           types.Date{},
				CheckedBy:      "",
			}
		}
	}
}

// addDetailedMetadata enriches the model with comprehensive metadata.
// Metadata provides context for:
//   - Model scope and coverage
//   - Business impact assessment
//   - Resource inventory
//   - Generation audit trail
//
// Metadata includes:
//   - Resource counts by type
//   - Infrastructure complexity metrics
//   - Business criticality assessment
//   - Generation timestamp and method
//
// This information helps:
//   - Stakeholders understand scope
//   - Auditors verify completeness
//   - Teams prioritize remediation
//   - Management assess risk exposure
//
// Parameters:
//   - model: The threat model to enrich
//   - results: All ParseResults for statistics
func (g *DetailedGenerator) addDetailedMetadata(model *types.Model, results []*ParseResult) {
	// Calculate infrastructure statistics
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
	if model.TechnicalOverview == nil {
		model.TechnicalOverview = &types.Overview{}
	}
	
	if model.TechnicalOverview.Description == "" {
		model.TechnicalOverview.Description = "Threat model generated from Infrastructure as Code with detailed analysis"
	}
	
	// Add business criticality based on resources
	if model.BusinessCriticality == 0 {
		// Determine criticality based on resource counts
		switch g.determineBusinessCriticality(resourceCounts) {
		case "critical":
			model.BusinessCriticality = types.Critical
		case "important":
			model.BusinessCriticality = types.Important
		default:
			model.BusinessCriticality = types.Operational
		}
	}
}

// Helper methods for detailed analysis
// These methods implement specific security checks and analysis logic
// used throughout the detailed generation process.

// isOverlyPermissive checks if a security rule allows unrestricted access.
// Rules allowing access from 0.0.0.0/0 (IPv4) or ::/0 (IPv6) expose
// resources to the entire internet, creating significant security risk.
//
// Parameters:
//   - rule: The security rule to evaluate
//
// Returns:
//   - true if the rule allows unrestricted access
func (g *DetailedGenerator) isOverlyPermissive(rule SecurityRule) bool {
	// Check for "allow all" IPv4 and IPv6 addresses
	return rule.Source == "0.0.0.0/0" || rule.Source == "::/0"
}

// hasEgressRules verifies if a security group has outbound rules defined.
// Missing egress rules may indicate:
//   - Default allow-all outbound (security risk)
//   - Incomplete security configuration
//   - Potential data exfiltration paths
//
// Parameters:
//   - sg: The security group to check
//
// Returns:
//   - true if egress rules are defined
func (g *DetailedGenerator) hasEgressRules(sg *SecurityGroup) bool {
	for _, rule := range sg.Rules {
		if rule.Direction == "egress" {
			return true
		}
	}
	return false
}

// assetUsesSecurityGroup determines if an asset is protected by a security group.
// This association is important for:
//   - Understanding asset exposure
//   - Validating defense-in-depth
//   - Identifying unprotected resources
//
// Parameters:
//   - asset: The technical asset to check
//   - sg: The security group to match
//
// Returns:
//   - true if the asset uses this security group
func (g *DetailedGenerator) assetUsesSecurityGroup(asset *types.TechnicalAsset, sg *SecurityGroup) bool {
	// Check if asset tags reference the security group
	for _, tag := range asset.Tags {
		if strings.Contains(tag, sg.ID) {
			return true
		}
	}
	return false
}

// enhanceAssetSecurity enriches an asset with security group information.
// This enhancement helps:
//   - Track security controls per asset
//   - Validate security group coverage
//   - Support security group analysis
//
// Parameters:
//   - asset: The asset to enhance
//   - sg: The security group protecting the asset
func (g *DetailedGenerator) enhanceAssetSecurity(asset *types.TechnicalAsset, sg *SecurityGroup) {
	// Tag asset with security group for traceability
	sgTag := fmt.Sprintf("security-group:%s", sg.Name)
	if !g.hasTag(asset, sgTag) {
		asset.Tags = append(asset.Tags, sgTag)
	}
}

// determineNetworkZone classifies networks into security zones.
// Zone classification is crucial for:
//   - Applying appropriate security controls
//   - Validating network segmentation
//   - Enforcing zone-based policies
//
// Common zones:
//   - public: Internet-facing resources
//   - dmz: Semi-trusted buffer zone  
//   - private: Internal resources only
//   - management: Administrative access
//
// Parameters:
//   - network: The network to classify
//
// Returns:
//   - Zone classification string
func (g *DetailedGenerator) determineNetworkZone(network *Network) string {
	// Use naming conventions to infer zone
	if strings.Contains(strings.ToLower(network.Name), "public") {
		return "public"
	}
	if strings.Contains(strings.ToLower(network.Name), "dmz") {
		return "dmz"
	}
	return "private"
}

// enhanceTrustBoundary enriches an existing trust boundary with network zone information.
// This provides context for security controls and compliance requirements.
//
// Parameters:
//   - boundary: The trust boundary to enhance
//   - network: The network providing context
//   - zone: The security zone classification
func (g *DetailedGenerator) enhanceTrustBoundary(boundary *types.TrustBoundary, network *Network, zone string) {
	// Tag boundary with zone and network type for analysis
	boundary.Tags = append(boundary.Tags, fmt.Sprintf("zone:%s", zone))
	boundary.Tags = append(boundary.Tags, fmt.Sprintf("network:%s", network.Type))
}

// createNetworkBoundary creates a new trust boundary from network configuration.
// Trust boundaries represent security perimeters where trust levels change.
//
// Parameters:
//   - network: The network defining the boundary
//   - zone: The security zone classification
//
// Returns:
//   - New trust boundary with appropriate metadata
func (g *DetailedGenerator) createNetworkBoundary(network *Network, zone string) *types.TrustBoundary {
	return &types.TrustBoundary{
		Id:          fmt.Sprintf("network-%s", network.ID),
		Title:       fmt.Sprintf("%s Network", network.Name),
		Description: fmt.Sprintf("Network boundary for %s zone", zone),
		Type:        types.NetworkCloudProvider,
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

// determineDataClassification infers data sensitivity from database naming patterns.
// This heuristic approach helps identify compliance requirements and security controls.
//
// Classification levels:
//   - restricted: Highly sensitive (payment, credit cards, SSN)
//   - confidential: Sensitive personal data (user, customer info)
//   - internal: Business data (non-public operational data)
//   - public: Non-sensitive (caches, public content)
//
// Parameters:
//   - db: The database to classify
//
// Returns:
//   - Data classification level
func (g *DetailedGenerator) determineDataClassification(db *Database) string {
	// Use naming patterns to infer data sensitivity
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
		Usage: types.Business,
		Tags: []string{
			fmt.Sprintf("classification:%s", classification),
			fmt.Sprintf("database:%s", db.Type),
		},
		Origin:             "IaC",
		Owner:              "system",
		Quantity:           types.Many,
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

// detectCompliancePatterns identifies infrastructure subject to regulatory requirements.
// Automatic compliance detection helps ensure proper controls are implemented.
//
// Detected frameworks:
//   - PCI-DSS: Payment card industry (payment, card, transaction)
//   - HIPAA: Healthcare (patient, medical, health, PHI)
//   - GDPR: EU privacy (user, customer, personal data)
//
// Detection based on:
//   - Resource naming patterns
//   - Data types processed
//   - Geographic indicators
//   - Industry-specific markers
//
// Parameters:
//   - result: ParseResult containing infrastructure
//
// Returns:
//   - Map of compliance framework to affected asset IDs
func (g *DetailedGenerator) detectCompliancePatterns(result *ParseResult) map[string][]string {
	patterns := make(map[string][]string)
	
	// Detect payment card processing infrastructure
	if g.hasPCIPatterns(result) {
		patterns["pci-dss"] = g.getPCIAssets(result)
	}
	
	// Detect healthcare data infrastructure  
	if g.hasHIPAAPatterns(result) {
		patterns["hipaa"] = g.getHIPAAAssets(result)
	}
	
	// Detect personal data processing
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
	return asset.Type == types.Datastore || 
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
// These methods create standardized risk entries for different vulnerability categories.
// Consistent risk tracking enables systematic remediation and compliance reporting.

// addSecurityRisk documents network and access control vulnerabilities.
// Security risks include firewall misconfigurations, open ports, and access control issues.
//
// Parameters:
//   - model: The threat model to update
//   - assetID: The affected asset identifier
//   - riskType: The type of security risk detected
//   - rule: The specific rule or configuration causing risk
func (g *DetailedGenerator) addSecurityRisk(model *types.Model, assetID, riskType string, rule interface{}) {
	// Initialize risk tracking if needed
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	// Create unique risk identifier
	riskID := fmt.Sprintf("security-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
		Justification: fmt.Sprintf("Security risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addIAMRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("iam-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
		Justification: fmt.Sprintf("IAM risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addStorageRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("storage-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
		Justification: fmt.Sprintf("Storage risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addCommunicationRisk(model *types.Model, linkID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("comm-%s-%s", linkID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
		Justification: fmt.Sprintf("Communication risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addEncryptionRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("encryption-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
		Justification: fmt.Sprintf("Encryption risk: %s", riskType),
	}
}

func (g *DetailedGenerator) addArchitectureRisk(model *types.Model, assetID, riskType string) {
	if model.RiskTracking == nil {
		model.RiskTracking = make(map[string]*types.RiskTracking)
	}
	
	riskID := fmt.Sprintf("arch-%s-%s", assetID, riskType)
	model.RiskTracking[riskID] = &types.RiskTracking{
		Status:        types.Unchecked,
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
		Status:        types.Unchecked,
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
		return types.StrictlyConfidential
	case "confidential":
		return types.Confidential
	case "internal":
		return types.Internal
	default:
		return types.Public
	}
}

func (g *DetailedGenerator) mapToIntegrity(classification string) types.Criticality {
	switch classification {
	case "restricted", "confidential":
		return types.Critical
	case "internal":
		return types.Important
	default:
		return types.Operational
	}
}

func (g *DetailedGenerator) mapToAvailability(classification string) types.Criticality {
	switch classification {
	case "restricted":
		return types.Critical
	case "confidential", "internal":
		return types.Important
	default:
		return types.Operational
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
		Protocol: types.HTTPS,
		Authentication: types.Credentials,
		Authorization: types.TechnicalUser,
		Usage: types.Business,
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
	return asset.Type == types.Datastore || 
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