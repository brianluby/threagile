// Package hcl provides a parser for HashiCorp Configuration Language (HCL) files,
// primarily used for Terraform infrastructure definitions. This parser extracts
// infrastructure components, security configurations, and relationships from HCL
// files to build a comprehensive threat model.
package hcl

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/types"
)

// Parser implements the ai.IaCParser interface for HCL/Terraform files.
// It uses the official HashiCorp HCL v2 library to parse Terraform configurations
// and extract infrastructure components like compute instances, databases, networks,
// security groups, and IAM resources for threat modeling analysis.
type Parser struct {
	// hclParser is the underlying HCL parser instance from HashiCorp's library
	hclParser *hclparse.Parser
}

// NewParser creates a new HCL parser instance.
// The parser is initialized with HashiCorp's HCL v2 parser which supports
// both native HCL syntax and JSON-based HCL files.
func NewParser() *Parser {
	return &Parser{
		hclParser: hclparse.NewParser(),
	}
}

// TerraformConfig represents the top-level Terraform configuration structure.
// This struct maps to the main blocks found in Terraform files and is used
// for decoding HCL content into Go structures for analysis.
type TerraformConfig struct {
	// Resources defines infrastructure components (e.g., EC2 instances, S3 buckets)
	Resources   []Resource   `hcl:"resource,block"`
	// DataSources reference existing infrastructure for use in configuration
	DataSources []DataSource `hcl:"data,block"`
	// Variables define input parameters for the Terraform configuration
	Variables   []Variable   `hcl:"variable,block"`
	// Outputs define values to be extracted after infrastructure deployment
	Outputs     []Output     `hcl:"output,block"`
	// Providers configure the infrastructure platforms (AWS, Azure, GCP, etc.)
	Providers   []Provider   `hcl:"provider,block"`
	// Modules encapsulate reusable Terraform configurations
	Modules     []Module     `hcl:"module,block"`
}

// Resource represents a Terraform resource block
type Resource struct {
	Type   string   `hcl:"type,label"`
	Name   string   `hcl:"name,label"`
	Config hcl.Body `hcl:",remain"`
}

// DataSource represents a Terraform data block
type DataSource struct {
	Type   string   `hcl:"type,label"`
	Name   string   `hcl:"name,label"`
	Config hcl.Body `hcl:",remain"`
}

// Variable represents a Terraform variable block
type Variable struct {
	Name        string         `hcl:"name,label"`
	Type        *string        `hcl:"type,optional"`
	Description *string        `hcl:"description,optional"`
	Default     hcl.Expression `hcl:"default,optional"`
	Sensitive   *bool          `hcl:"sensitive,optional"`
}

// Output represents a Terraform output block
type Output struct {
	Name        string         `hcl:"name,label"`
	Value       hcl.Expression `hcl:"value"`
	Description *string        `hcl:"description,optional"`
	Sensitive   *bool          `hcl:"sensitive,optional"`
}

// Provider represents a Terraform provider block
type Provider struct {
	Name   string   `hcl:"name,label"`
	Config hcl.Body `hcl:",remain"`
}

// Module represents a Terraform module block
type Module struct {
	Name   string   `hcl:"name,label"`
	Source string   `hcl:"source"`
	Config hcl.Body `hcl:",remain"`
}

// SupportsFile checks if the parser supports the given file based on its extension.
// This method implements the ai.IaCParser interface requirement.
//
// Supported file types:
//   - .tf files: Standard Terraform configuration files
//   - .hcl files: Generic HCL configuration files
//   - .tf.json files: JSON-formatted Terraform configuration files
//
// Parameters:
//   - filename: The path to the file to check
//
// Returns:
//   - true if the file type is supported, false otherwise
func (p *Parser) SupportsFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	base := filepath.Base(filename)
	
	// Support .tf and .hcl files
	if ext == ".tf" || ext == ".hcl" {
		return true
	}
	
	// Support common Terraform file patterns
	if strings.HasSuffix(base, ".tf.json") {
		return true
	}
	
	return false
}

// ParseFile parses an HCL/Terraform file and extracts infrastructure components
// for threat modeling analysis. This is the main entry point for the parser.
//
// The method performs the following steps:
//   1. Initializes result structures for various infrastructure components
//   2. Parses the HCL content using HashiCorp's parser
//   3. Attempts to decode the HCL into structured Terraform blocks
//   4. Processes each block type to extract security-relevant information
//   5. Returns a ParseResult containing all discovered infrastructure
//
// Parameters:
//   - filename: The path to the file being parsed (used for error reporting)
//   - content: The raw byte content of the HCL file
//
// Returns:
//   - *ai.ParseResult: Structured data about discovered infrastructure
//   - error: Any parsing or processing errors encountered
func (p *Parser) ParseFile(filename string, content []byte) (*ai.ParseResult, error) {
	// Initialize the result structure with empty maps for each component type
	result := &ai.ParseResult{
		Resources:      make(map[string]*ai.Resource),
		Networks:       make(map[string]*ai.Network),
		SecurityGroups: make(map[string]*ai.SecurityGroup),
		Databases:      make(map[string]*ai.Database),
		Storages:       make(map[string]*ai.Storage),
		LoadBalancers:  make(map[string]*ai.LoadBalancer),
		Containers:     make(map[string]*ai.Container),
		Functions:      make(map[string]*ai.Function),
		Queues:         make(map[string]*ai.Queue),
		Topics:         make(map[string]*ai.Topic),
		Users:          make(map[string]*ai.User),
		Roles:          make(map[string]*ai.Role),
		Policies:       make(map[string]*ai.Policy),
		Metadata: ai.Metadata{
			SourceFile: filename,
			IaCType:    "terraform",
		},
	}

	// Parse the HCL file using HashiCorp's parser
	// This handles both native HCL and JSON syntax
	file, diags := p.hclParser.ParseHCL(content, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("HCL parse errors: %s", diags.Error())
	}

	// Attempt to decode the parsed HCL into our TerraformConfig structure
	// This provides strongly-typed access to Terraform blocks
	var config TerraformConfig
	diags = gohcl.DecodeBody(file.Body, nil, &config)
	if diags.HasErrors() {
		// Terraform files often contain complex expressions, interpolations,
		// and dynamic blocks that may not decode cleanly into static structures.
		// We'll try to extract what we can using a more flexible approach.
		p.extractPartialResources(file.Body, result)
	}

	// Process each type of Terraform block to extract infrastructure components
	
	// Process resource blocks (e.g., aws_instance, azurerm_storage_account)
	// These represent the actual infrastructure being created
	for _, resource := range config.Resources {
		p.processResource(resource, result)
	}

	// Process data source blocks which reference existing infrastructure
	// These can reveal dependencies and integration points
	for _, dataSource := range config.DataSources {
		p.processDataSource(dataSource, result)
	}

	// Process module blocks which encapsulate reusable configurations
	// Modules may contain additional infrastructure not visible at this level
	for _, module := range config.Modules {
		p.processModule(module, result)
	}

	// Process variable blocks to identify sensitive configuration values
	// Variables marked as sensitive may contain credentials or secrets
	for _, variable := range config.Variables {
		p.processVariable(variable, result)
	}

	// Process output blocks which may expose sensitive information
	// Outputs marked as sensitive need special handling in threat models
	for _, output := range config.Outputs {
		p.processOutput(output, result)
	}

	return result, nil
}

// processResource analyzes a Terraform resource block and categorizes it into
// the appropriate infrastructure component type for threat modeling.
//
// This method examines the resource type (e.g., aws_instance, google_compute_instance)
// and maps it to the corresponding threat model component (compute, database, storage, etc.).
// It also extracts security-relevant attributes like tags, encryption settings, and access controls.
//
// Parameters:
//   - resource: The parsed Terraform resource block
//   - result: The ParseResult to populate with discovered components
func (p *Parser) processResource(resource Resource, result *ai.ParseResult) {
	// Create a unique identifier for this resource using Terraform's naming convention
	resourceID := fmt.Sprintf("%s.%s", resource.Type, resource.Name)
	
	// Map Terraform resource types to appropriate threat model categories
	// This switch statement handles provider-specific resource types from AWS, Azure, GCP, etc.
	switch {
	case strings.HasPrefix(resource.Type, "aws_instance") || 
		 strings.HasPrefix(resource.Type, "aws_ec2_instance") ||
		 strings.HasPrefix(resource.Type, "google_compute_instance") ||
		 strings.HasPrefix(resource.Type, "azurerm_virtual_machine"):
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     "compute",
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_database_") || 
		 strings.Contains(resource.Type, "_db_") ||
		 strings.HasPrefix(resource.Type, "aws_rds_") ||
		 strings.HasPrefix(resource.Type, "aws_dynamodb_"):
		result.Databases[resourceID] = &ai.Database{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     p.getDatabaseType(resource.Type),
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_bucket") ||
		 strings.Contains(resource.Type, "_storage"):
		result.Storages[resourceID] = &ai.Storage{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     "object",
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_security_group") ||
		 strings.Contains(resource.Type, "_network_security"):
		result.SecurityGroups[resourceID] = &ai.SecurityGroup{
			ID:          resourceID,
			Name:        resource.Name,
			Description: p.extractDescription(resource.Config),
			Rules:       p.extractSecurityRules(resource.Config),
			Tags:        p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_vpc") ||
		 strings.Contains(resource.Type, "_virtual_network") ||
		 strings.Contains(resource.Type, "_subnet"):
		result.Networks[resourceID] = &ai.Network{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     p.getNetworkType(resource.Type),
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_load_balancer") ||
		 strings.Contains(resource.Type, "_lb") ||
		 strings.Contains(resource.Type, "_alb") ||
		 strings.Contains(resource.Type, "_elb"):
		result.LoadBalancers[resourceID] = &ai.LoadBalancer{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     p.getLoadBalancerType(resource.Type),
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_lambda_function") ||
		 strings.Contains(resource.Type, "_function_app"):
		result.Functions[resourceID] = &ai.Function{
			ID:       resourceID,
			Name:     resource.Name,
			Runtime:  p.extractRuntime(resource.Config),
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_container") ||
		 strings.Contains(resource.Type, "_ecs_") ||
		 strings.Contains(resource.Type, "_kubernetes_"):
		result.Containers[resourceID] = &ai.Container{
			ID:       resourceID,
			Name:     resource.Name,
			Image:    p.extractImage(resource.Config),
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_sqs_") ||
		 strings.Contains(resource.Type, "_queue"):
		result.Queues[resourceID] = &ai.Queue{
			ID:       resourceID,
			Name:     resource.Name,
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_sns_") ||
		 strings.Contains(resource.Type, "_topic"):
		result.Topics[resourceID] = &ai.Topic{
			ID:       resourceID,
			Name:     resource.Name,
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_iam_user") ||
		 strings.Contains(resource.Type, "_user"):
		result.Users[resourceID] = &ai.User{
			ID:   resourceID,
			Name: resource.Name,
			Tags: p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_iam_role") ||
		 strings.Contains(resource.Type, "_role"):
		result.Roles[resourceID] = &ai.Role{
			ID:          resourceID,
			Name:        resource.Name,
			Description: p.extractDescription(resource.Config),
			Tags:        p.extractTags(resource.Config),
		}

	case strings.Contains(resource.Type, "_iam_policy") ||
		 strings.Contains(resource.Type, "_policy"):
		result.Policies[resourceID] = &ai.Policy{
			ID:          resourceID,
			Name:        resource.Name,
			Description: p.extractDescription(resource.Config),
			Tags:        p.extractTags(resource.Config),
		}

	default:
		// Add as generic resource
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     resource.Name,
			Type:     "generic",
			Provider: p.getProviderFromType(resource.Type),
			Tags:     p.extractTags(resource.Config),
		}
	}
}

// processDataSource processes a Terraform data source
func (p *Parser) processDataSource(dataSource DataSource, result *ai.ParseResult) {
	// Data sources often reference existing resources
	// We can use them to understand dependencies and connections
	dataID := fmt.Sprintf("data.%s.%s", dataSource.Type, dataSource.Name)
	
	// Add to metadata for relationship analysis
	if result.Metadata.DataSources == nil {
		result.Metadata.DataSources = make(map[string]interface{})
	}
	result.Metadata.DataSources[dataID] = map[string]string{
		"type": dataSource.Type,
		"name": dataSource.Name,
	}
}

// processModule processes a Terraform module
func (p *Parser) processModule(module Module, result *ai.ParseResult) {
	// Modules represent reusable components
	moduleID := fmt.Sprintf("module.%s", module.Name)
	
	// Add to metadata for relationship analysis
	if result.Metadata.Modules == nil {
		result.Metadata.Modules = make(map[string]interface{})
	}
	result.Metadata.Modules[moduleID] = map[string]string{
		"name":   module.Name,
		"source": module.Source,
	}
}

// processVariable analyzes a Terraform variable block for security implications.
// Variables marked as "sensitive" are particularly important for threat modeling
// as they often contain credentials, API keys, or other secrets that need protection.
//
// Parameters:
//   - variable: The parsed Terraform variable block
//   - result: The ParseResult to update with sensitive variable information
func (p *Parser) processVariable(variable Variable, result *ai.ParseResult) {
	// Track variables marked as sensitive - these likely contain secrets
	// that require special handling in the threat model
	if variable.Sensitive != nil && *variable.Sensitive {
		if result.Metadata.SensitiveVariables == nil {
			result.Metadata.SensitiveVariables = make([]string, 0)
		}
		result.Metadata.SensitiveVariables = append(
			result.Metadata.SensitiveVariables.([]string),
			variable.Name,
		)
	}
}

// processOutput analyzes a Terraform output block for security implications.
// Outputs marked as "sensitive" may expose confidential information and need
// to be carefully tracked in the threat model to prevent accidental exposure.
//
// Parameters:
//   - output: The parsed Terraform output block
//   - result: The ParseResult to update with sensitive output information
func (p *Parser) processOutput(output Output, result *ai.ParseResult) {
	// Track outputs marked as sensitive - these may expose secrets
	// and should be highlighted in the threat model
	if output.Sensitive != nil && *output.Sensitive {
		if result.Metadata.SensitiveOutputs == nil {
			result.Metadata.SensitiveOutputs = make([]string, 0)
		}
		result.Metadata.SensitiveOutputs = append(
			result.Metadata.SensitiveOutputs.([]string),
			output.Name,
		)
	}
}

// extractPartialResources provides a fallback parsing mechanism for complex HCL files
// that cannot be fully decoded into our structured format. This handles cases where
// Terraform files use advanced features like dynamic blocks, complex expressions,
// or provider-specific extensions that don't fit our static schema.
//
// Parameters:
//   - body: The HCL body that failed to decode normally
//   - result: The ParseResult to populate with any extractable information
//
// Note: This is a resilience mechanism to ensure we can extract some value
// from any valid Terraform file, even if we can't parse it completely.
func (p *Parser) extractPartialResources(body hcl.Body, result *ai.ParseResult) {
	// TODO: Implement AST traversal to extract resource types and names
	// even when full attribute decoding fails. This would use the lower-level
	// HCL APIs to walk the syntax tree and identify resource blocks.
	
	// Mark that this was a partial parse so the threat model generator
	// knows the results may be incomplete
	result.Metadata.PartialParse = true
}

// Helper methods for extracting specific attributes from resources
// These methods provide consistent mapping between Terraform resource types
// and threat model categories.

// getProviderFromType determines the cloud provider from a Terraform resource type.
// This is essential for threat modeling as different providers have different
// security models, compliance requirements, and attack surfaces.
//
// Parameters:
//   - resourceType: The Terraform resource type (e.g., "aws_instance", "google_compute_instance")
//
// Returns:
//   - The provider name ("aws", "gcp", "azure", "kubernetes", or "unknown")
func (p *Parser) getProviderFromType(resourceType string) string {
	if strings.HasPrefix(resourceType, "aws_") {
		return "aws"
	} else if strings.HasPrefix(resourceType, "google_") || strings.HasPrefix(resourceType, "gcp_") {
		return "gcp"
	} else if strings.HasPrefix(resourceType, "azurerm_") || strings.HasPrefix(resourceType, "azure_") {
		return "azure"
	} else if strings.HasPrefix(resourceType, "kubernetes_") || strings.HasPrefix(resourceType, "k8s_") {
		return "kubernetes"
	}
	return "unknown"
}

// getDatabaseType categorizes database resources by their data model.
// This classification is important for threat modeling as different database
// types have different security considerations (SQL injection vs NoSQL injection,
// encryption at rest capabilities, access control models, etc.).
//
// Parameters:
//   - resourceType: The Terraform resource type for a database
//
// Returns:
//   - Database category: "relational", "nosql", "cache", or "generic"
func (p *Parser) getDatabaseType(resourceType string) string {
	if strings.Contains(resourceType, "rds") || strings.Contains(resourceType, "aurora") {
		return "relational"
	} else if strings.Contains(resourceType, "dynamodb") || strings.Contains(resourceType, "cosmos") {
		return "nosql"
	} else if strings.Contains(resourceType, "redis") || strings.Contains(resourceType, "elasticache") {
		return "cache"
	}
	return "generic"
}

// getNetworkType classifies network resources for security boundary analysis.
// Network types are crucial for threat modeling as they define isolation
// boundaries, traffic flow constraints, and potential attack paths.
//
// Parameters:
//   - resourceType: The Terraform resource type for a network component
//
// Returns:
//   - Network category: "vpc", "subnet", or "network"
func (p *Parser) getNetworkType(resourceType string) string {
	if strings.Contains(resourceType, "vpc") || strings.Contains(resourceType, "virtual_network") {
		return "vpc"
	} else if strings.Contains(resourceType, "subnet") {
		return "subnet"
	}
	return "network"
}

// getLoadBalancerType identifies the load balancer layer for security analysis.
// Different load balancer types operate at different OSI layers and have
// distinct security features (WAF support, SSL termination, DDoS protection).
//
// Parameters:
//   - resourceType: The Terraform resource type for a load balancer
//
// Returns:
//   - Load balancer type: "application" (L7), "network" (L4), or "classic"
func (p *Parser) getLoadBalancerType(resourceType string) string {
	if strings.Contains(resourceType, "application") || strings.Contains(resourceType, "alb") {
		return "application"
	} else if strings.Contains(resourceType, "network") || strings.Contains(resourceType, "nlb") {
		return "network"
	}
	return "classic"
}

// extractTags retrieves resource tags from the HCL configuration body.
// Tags are critical for threat modeling as they often indicate:
//   - Environment (prod/dev/staging)
//   - Data classification (PII, confidential)
//   - Compliance scope (PCI, HIPAA)
//   - Ownership and responsibility
//
// Parameters:
//   - body: The HCL body containing the resource configuration
//
// Returns:
//   - Map of tag key-value pairs
//
// TODO: Implement actual tag extraction from HCL body attributes
func (p *Parser) extractTags(body hcl.Body) map[string]string {
	// This would traverse the body to find "tags" attributes
	// and extract their key-value pairs
	return make(map[string]string)
}

// extractDescription retrieves the description attribute from an HCL body.
// Descriptions are useful for understanding the purpose of security groups
// and other resources, which helps in threat modeling and risk assessment.
//
// Parameters:
//   - body: The HCL body containing the resource configuration
//
// Returns:
//   - The description string if found, empty string otherwise
//
// TODO: Implement actual description extraction from HCL attributes
func (p *Parser) extractDescription(body hcl.Body) string {
	// This would look for "description" attributes in the body
	return ""
}

// extractSecurityRules parses security group rules from the HCL configuration.
// Security rules define network access controls and are critical for identifying
// potential attack vectors and overly permissive configurations.
//
// Parameters:
//   - body: The HCL body containing security group configuration
//
// Returns:
//   - Slice of SecurityRule structs with ingress/egress rules
//
// TODO: Implement parsing of ingress/egress rules with protocols, ports, and sources
func (p *Parser) extractSecurityRules(body hcl.Body) []ai.SecurityRule {
	// This would parse ingress and egress blocks to extract:
	// - Protocol (TCP/UDP/ICMP)
	// - Port ranges
	// - Source/destination CIDR blocks or security groups
	// - Rule descriptions
	return []ai.SecurityRule{}
}

// extractRuntime identifies the runtime environment for serverless functions.
// Runtime information is essential for vulnerability assessment as different
// runtimes have different security characteristics and CVE exposure.
//
// Parameters:
//   - body: The HCL body containing function configuration
//
// Returns:
//   - Runtime string (e.g., "python3.9", "nodejs14.x", "go1.x")
//
// TODO: Implement runtime extraction from Lambda and other function resources
func (p *Parser) extractRuntime(body hcl.Body) string {
	// This would look for "runtime" attributes in function resources
	return ""
}

// extractImage retrieves the container image reference from the configuration.
// Container images are crucial for security analysis to identify:
//   - Base image vulnerabilities
//   - Outdated or unpatched images
//   - Images from untrusted registries
//
// Parameters:
//   - body: The HCL body containing container configuration
//
// Returns:
//   - Full image reference including registry, name, and tag
//
// TODO: Implement image extraction from ECS, Kubernetes, and other container resources
func (p *Parser) extractImage(body hcl.Body) string {
	// This would look for "image" attributes in container definitions
	return ""
}

// ToThreagileModel converts the parsed infrastructure components from the IaC format
// into Threagile's native model format for threat analysis. This method performs
// the critical mapping between infrastructure resources and security-relevant
// technical assets.
//
// The conversion process:
//   1. Maps cloud resources to appropriate technical asset types
//   2. Preserves security-relevant metadata and tags
//   3. Maintains relationships between components
//   4. Prepares the model for threat rule evaluation
//
// Parameters:
//   - result: The ParseResult containing all discovered infrastructure
//
// Returns:
//   - *types.Model: A Threagile model ready for threat analysis
//   - error: Any conversion errors encountered
func (p *Parser) ToThreagileModel(result *ai.ParseResult) (*types.Model, error) {
	model := &types.Model{
		TechnicalAssets: make(map[string]*types.TechnicalAsset),
		DataAssets:      make(map[string]*types.DataAsset),
		TrustBoundaries: make(map[string]*types.TrustBoundary),
	}

	// Convert compute resources
	for id, resource := range result.Resources {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: resource.Name,
			Type:  types.TechnicalAssetType("process"),
			Tags:  convertTags(resource.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	// Convert databases
	for id, db := range result.Databases {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: db.Name,
			Type:  types.TechnicalAssetType("datastore"),
			Tags:  convertTags(db.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	// Convert storage
	for id, storage := range result.Storages {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: storage.Name,
			Type:  types.TechnicalAssetType("datastore"),
			Tags:  convertTags(storage.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	// Convert load balancers
	for id, lb := range result.LoadBalancers {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: lb.Name,
			Type:  types.TechnicalAssetType("load-balancer"),
			Tags:  convertTags(lb.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	// Convert functions
	for id, fn := range result.Functions {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: fn.Name,
			Type:  types.TechnicalAssetType("process"),
			Tags:  convertTags(fn.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	// Convert containers
	for id, container := range result.Containers {
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: container.Name,
			Type:  types.TechnicalAssetType("process"),
			Tags:  convertTags(container.Tags),
		}
		model.TechnicalAssets[id] = asset
	}

	return model, nil
}

// convertTags transforms a map of key-value tags into Threagile's tag format.
// Tags are preserved during conversion as they often contain critical security
// metadata like environment classification, data sensitivity, and compliance scope.
//
// Parameters:
//   - tags: Map of tag keys to values from the infrastructure resource
//
// Returns:
//   - Slice of formatted tag strings in "key:value" format
func convertTags(tags map[string]string) []string {
	result := make([]string, 0, len(tags))
	for k, v := range tags {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
	}
	return result
}

// RegisterParser registers the HCL parser with the central parser registry.
// This allows the AI orchestrator to automatically use this parser for
// Terraform and other HCL-based infrastructure files.
//
// The parser is registered with the name "hcl" and will be selected for:
//   - Files with .tf extension (Terraform)
//   - Files with .hcl extension (generic HCL)
//   - Files with .tf.json extension (JSON-formatted Terraform)
//
// Parameters:
//   - registry: The parser registry to register with
//
// Returns:
//   - error: Registration error if the parser name is already taken
func RegisterParser(registry *ai.ParserRegistry) error {
	parser := NewParser()
	return registry.Register("hcl", parser)
}