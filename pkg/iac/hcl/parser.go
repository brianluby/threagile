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

// Parser implements the ai.IaCParser interface for HCL/Terraform files
type Parser struct {
	hclParser *hclparse.Parser
}

// NewParser creates a new HCL parser
func NewParser() *Parser {
	return &Parser{
		hclParser: hclparse.NewParser(),
	}
}

// TerraformConfig represents the top-level Terraform configuration
type TerraformConfig struct {
	Resources   []Resource   `hcl:"resource,block"`
	DataSources []DataSource `hcl:"data,block"`
	Variables   []Variable   `hcl:"variable,block"`
	Outputs     []Output     `hcl:"output,block"`
	Providers   []Provider   `hcl:"provider,block"`
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

// SupportsFile checks if the parser supports the given file
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

// ParseFile parses an HCL/Terraform file and returns infrastructure components
func (p *Parser) ParseFile(filename string, content []byte) (*ai.ParseResult, error) {
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

	// Parse the HCL file
	file, diags := p.hclParser.ParseHCL(content, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("HCL parse errors: %s", diags.Error())
	}

	// Decode into our structure
	var config TerraformConfig
	diags = gohcl.DecodeBody(file.Body, nil, &config)
	if diags.HasErrors() {
		// Try to extract what we can even with errors
		// Many Terraform files have complex expressions that may not fully decode
		p.extractPartialResources(file.Body, result)
	}

	// Process resources
	for _, resource := range config.Resources {
		p.processResource(resource, result)
	}

	// Process data sources
	for _, dataSource := range config.DataSources {
		p.processDataSource(dataSource, result)
	}

	// Process modules
	for _, module := range config.Modules {
		p.processModule(module, result)
	}

	// Process variables for security analysis
	for _, variable := range config.Variables {
		p.processVariable(variable, result)
	}

	// Process outputs for security analysis
	for _, output := range config.Outputs {
		p.processOutput(output, result)
	}

	return result, nil
}

// processResource processes a Terraform resource and adds it to the result
func (p *Parser) processResource(resource Resource, result *ai.ParseResult) {
	resourceID := fmt.Sprintf("%s.%s", resource.Type, resource.Name)
	
	// Map Terraform resource types to appropriate categories
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

// processVariable processes a Terraform variable
func (p *Parser) processVariable(variable Variable, result *ai.ParseResult) {
	// Check for sensitive variables that might contain secrets
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

// processOutput processes a Terraform output
func (p *Parser) processOutput(output Output, result *ai.ParseResult) {
	// Check for sensitive outputs
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

// extractPartialResources attempts to extract resources even when full decoding fails
func (p *Parser) extractPartialResources(body hcl.Body, result *ai.ParseResult) {
	// This is a fallback method to extract what we can from complex HCL files
	// Implementation would use lower-level HCL APIs to traverse the AST
	// For now, we'll just note that partial extraction was attempted
	result.Metadata.PartialParse = true
}

// Helper methods for extracting specific attributes

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

func (p *Parser) getNetworkType(resourceType string) string {
	if strings.Contains(resourceType, "vpc") || strings.Contains(resourceType, "virtual_network") {
		return "vpc"
	} else if strings.Contains(resourceType, "subnet") {
		return "subnet"
	}
	return "network"
}

func (p *Parser) getLoadBalancerType(resourceType string) string {
	if strings.Contains(resourceType, "application") || strings.Contains(resourceType, "alb") {
		return "application"
	} else if strings.Contains(resourceType, "network") || strings.Contains(resourceType, "nlb") {
		return "network"
	}
	return "classic"
}

func (p *Parser) extractTags(body hcl.Body) map[string]string {
	// This would extract tags from the HCL body
	// For now, return empty map
	return make(map[string]string)
}

func (p *Parser) extractDescription(body hcl.Body) string {
	// This would extract description from the HCL body
	return ""
}

func (p *Parser) extractSecurityRules(body hcl.Body) []ai.SecurityRule {
	// This would extract security rules from the HCL body
	return []ai.SecurityRule{}
}

func (p *Parser) extractRuntime(body hcl.Body) string {
	// This would extract runtime from the HCL body
	return ""
}

func (p *Parser) extractImage(body hcl.Body) string {
	// This would extract container image from the HCL body
	return ""
}

// ToThreagileModel converts parsed infrastructure to Threagile model components
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

func convertTags(tags map[string]string) []string {
	result := make([]string, 0, len(tags))
	for k, v := range tags {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
	}
	return result
}

// RegisterParser registers the HCL parser with the parser registry
func RegisterParser(registry *ai.ParserRegistry) error {
	parser := NewParser()
	return registry.Register("hcl", parser)
}