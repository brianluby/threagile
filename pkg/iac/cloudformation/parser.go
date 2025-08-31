package cloudformation

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/awslabs/goformation/v7"
	"github.com/awslabs/goformation/v7/cloudformation"
	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/types"
	"gopkg.in/yaml.v3"
)

// Parser implements the ai.IaCParser interface for CloudFormation templates
type Parser struct{}

// NewParser creates a new CloudFormation parser
func NewParser() *Parser {
	return &Parser{}
}

// SupportsFile checks if the parser supports the given file
func (p *Parser) SupportsFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	base := strings.ToLower(filepath.Base(filename))
	
	// Support common CloudFormation file patterns
	if ext == ".yaml" || ext == ".yml" || ext == ".json" {
		// Check for CloudFormation-specific naming patterns
		if strings.Contains(base, "template") ||
			strings.Contains(base, "stack") ||
			strings.Contains(base, "cloudformation") ||
			strings.Contains(base, "cfn") ||
			strings.HasPrefix(base, "cf-") {
			return true
		}
		
		// Also support generic YAML/JSON that might be CloudFormation
		// We'll validate the content in ParseFile
		return true
	}
	
	return false
}

// ParseFile parses a CloudFormation template and returns infrastructure components
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
			IaCType:    "cloudformation",
		},
	}

	// Parse the CloudFormation template using GoFormation
	template, err := goformation.ParseJSON(content)
	if err != nil {
		// Try parsing as YAML if JSON fails
		template, err = goformation.ParseYAML(content)
		if err != nil {
			// Check if this is actually a CloudFormation template
			if !p.isCloudFormationTemplate(content) {
				return nil, fmt.Errorf("file does not appear to be a CloudFormation template")
			}
			return nil, fmt.Errorf("failed to parse CloudFormation template: %w", err)
		}
	}

	// Process all resources in the template
	for name, resource := range template.Resources {
		p.processResource(name, resource, result)
	}

	// Process parameters for metadata
	if template.Parameters != nil {
		p.processParameters(template.Parameters, result)
	}

	// Process outputs for metadata
	if template.Outputs != nil {
		p.processOutputs(template.Outputs, result)
	}

	return result, nil
}

// isCloudFormationTemplate checks if content appears to be a CloudFormation template
func (p *Parser) isCloudFormationTemplate(content []byte) bool {
	// Try to unmarshal as JSON first
	var jsonData map[string]interface{}
	if err := json.Unmarshal(content, &jsonData); err == nil {
		// Check for CloudFormation-specific keys
		if _, hasResources := jsonData["Resources"]; hasResources {
			return true
		}
		if _, hasAWSVersion := jsonData["AWSTemplateFormatVersion"]; hasAWSVersion {
			return true
		}
	}

	// Try YAML
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(content, &yamlData); err == nil {
		// Check for CloudFormation-specific keys
		if _, hasResources := yamlData["Resources"]; hasResources {
			return true
		}
		if _, hasAWSVersion := yamlData["AWSTemplateFormatVersion"]; hasAWSVersion {
			return true
		}
	}

	return false
}

// processResource processes a CloudFormation resource and adds it to the result
func (p *Parser) processResource(name string, resource cloudformation.Resource, result *ai.ParseResult) {
	resourceType := resource.AWSCloudFormationType()
	resourceID := name

	switch resourceType {
	// Compute resources
	case "AWS::EC2::Instance":
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     name,
			Type:     "ec2",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Database resources
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
		result.Databases[resourceID] = &ai.Database{
			ID:       resourceID,
			Name:     name,
			Type:     "relational",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::DynamoDB::Table":
		result.Databases[resourceID] = &ai.Database{
			ID:       resourceID,
			Name:     name,
			Type:     "nosql",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup":
		result.Databases[resourceID] = &ai.Database{
			ID:       resourceID,
			Name:     name,
			Type:     "cache",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Storage resources
	case "AWS::S3::Bucket":
		result.Storages[resourceID] = &ai.Storage{
			ID:       resourceID,
			Name:     name,
			Type:     "object",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::EFS::FileSystem":
		result.Storages[resourceID] = &ai.Storage{
			ID:       resourceID,
			Name:     name,
			Type:     "file",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Network resources
	case "AWS::EC2::VPC":
		result.Networks[resourceID] = &ai.Network{
			ID:       resourceID,
			Name:     name,
			Type:     "vpc",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::EC2::Subnet":
		result.Networks[resourceID] = &ai.Network{
			ID:       resourceID,
			Name:     name,
			Type:     "subnet",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::EC2::SecurityGroup":
		result.SecurityGroups[resourceID] = &ai.SecurityGroup{
			ID:          resourceID,
			Name:        name,
			Description: p.extractDescription(resource),
			Rules:       p.extractSecurityRules(resource),
			Tags:        p.extractTags(resource),
		}

	// Load balancer resources
	case "AWS::ElasticLoadBalancing::LoadBalancer":
		result.LoadBalancers[resourceID] = &ai.LoadBalancer{
			ID:       resourceID,
			Name:     name,
			Type:     "classic",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::ElasticLoadBalancingV2::LoadBalancer":
		result.LoadBalancers[resourceID] = &ai.LoadBalancer{
			ID:       resourceID,
			Name:     name,
			Type:     "application",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Serverless resources
	case "AWS::Lambda::Function":
		result.Functions[resourceID] = &ai.Function{
			ID:       resourceID,
			Name:     name,
			Runtime:  p.extractRuntime(resource),
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Container resources
	case "AWS::ECS::Service", "AWS::ECS::TaskDefinition":
		result.Containers[resourceID] = &ai.Container{
			ID:       resourceID,
			Name:     name,
			Image:    p.extractContainerImage(resource),
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::EKS::Cluster":
		result.Containers[resourceID] = &ai.Container{
			ID:       resourceID,
			Name:     name,
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Messaging resources
	case "AWS::SQS::Queue":
		result.Queues[resourceID] = &ai.Queue{
			ID:       resourceID,
			Name:     name,
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	case "AWS::SNS::Topic":
		result.Topics[resourceID] = &ai.Topic{
			ID:       resourceID,
			Name:     name,
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// IAM resources
	case "AWS::IAM::User":
		result.Users[resourceID] = &ai.User{
			ID:   resourceID,
			Name: name,
			Tags: p.extractTags(resource),
		}

	case "AWS::IAM::Role":
		result.Roles[resourceID] = &ai.Role{
			ID:          resourceID,
			Name:        name,
			Description: p.extractDescription(resource),
			Tags:        p.extractTags(resource),
		}

	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
		result.Policies[resourceID] = &ai.Policy{
			ID:          resourceID,
			Name:        name,
			Description: p.extractDescription(resource),
			Tags:        p.extractTags(resource),
		}

	// API Gateway
	case "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api":
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     name,
			Type:     "api-gateway",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}

	// Default case for unrecognized resources
	default:
		// Still capture as generic resource
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     name,
			Type:     "generic",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}
	}
}

// processParameters processes CloudFormation parameters
func (p *Parser) processParameters(parameters map[string]interface{}, result *ai.ParseResult) {
	if result.Metadata.Parameters == nil {
		result.Metadata.Parameters = make(map[string]interface{})
	}
	
	for name, param := range parameters {
		result.Metadata.Parameters[name] = param
		
		// Check for sensitive parameters
		if p.isSensitiveParameter(name) {
			if result.Metadata.SensitiveVariables == nil {
				result.Metadata.SensitiveVariables = make([]string, 0)
			}
			result.Metadata.SensitiveVariables = append(
				result.Metadata.SensitiveVariables.([]string),
				name,
			)
		}
	}
}

// processOutputs processes CloudFormation outputs
func (p *Parser) processOutputs(outputs map[string]interface{}, result *ai.ParseResult) {
	if result.Metadata.Outputs == nil {
		result.Metadata.Outputs = make(map[string]interface{})
	}
	
	for name, output := range outputs {
		result.Metadata.Outputs[name] = output
		
		// Check for sensitive outputs
		if p.isSensitiveOutput(name) {
			if result.Metadata.SensitiveOutputs == nil {
				result.Metadata.SensitiveOutputs = make([]string, 0)
			}
			result.Metadata.SensitiveOutputs = append(
				result.Metadata.SensitiveOutputs.([]string),
				name,
			)
		}
	}
}

// Helper methods for extracting resource properties

func (p *Parser) extractTags(resource cloudformation.Resource) map[string]string {
	tags := make(map[string]string)
	
	// Try to extract tags from the resource
	// This would need to be implemented based on the specific resource type
	// For now, return empty map
	return tags
}

func (p *Parser) extractDescription(resource cloudformation.Resource) string {
	// Extract description from resource properties
	// Implementation would depend on resource type
	return ""
}

func (p *Parser) extractSecurityRules(resource cloudformation.Resource) []ai.SecurityRule {
	rules := []ai.SecurityRule{}
	
	// Extract security rules from SecurityGroup resource
	// This would need proper implementation based on GoFormation types
	return rules
}

func (p *Parser) extractRuntime(resource cloudformation.Resource) string {
	// Extract runtime from Lambda function
	// Implementation would depend on GoFormation Lambda types
	return ""
}

func (p *Parser) extractContainerImage(resource cloudformation.Resource) string {
	// Extract container image from ECS TaskDefinition
	// Implementation would depend on GoFormation ECS types
	return ""
}

func (p *Parser) isSensitiveParameter(name string) bool {
	lowerName := strings.ToLower(name)
	sensitiveKeywords := []string{
		"password", "secret", "key", "token", "credential",
		"api", "private", "auth", "cert", "ssh",
	}
	
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerName, keyword) {
			return true
		}
	}
	return false
}

func (p *Parser) isSensitiveOutput(name string) bool {
	return p.isSensitiveParameter(name) // Use same logic
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
		assetType := types.TechnicalAssetType("process")
		if resource.Type == "api-gateway" {
			assetType = types.TechnicalAssetType("gateway")
		}
		
		asset := &types.TechnicalAsset{
			Id:    id,
			Title: resource.Name,
			Type:  assetType,
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

	// Create trust boundaries based on networks
	for id, network := range result.Networks {
		if network.Type == "vpc" {
			boundary := &types.TrustBoundary{
				Id:    id,
				Title: network.Name,
				Type:  types.TrustBoundaryType("network-cloud-provider"),
				Tags:  convertTags(network.Tags),
			}
			model.TrustBoundaries[id] = boundary
		}
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

// RegisterParser registers the CloudFormation parser with the parser registry
func RegisterParser(registry *ai.ParserRegistry) error {
	parser := NewParser()
	return registry.Register("cloudformation", parser)
}