// Package cloudformation provides a parser for AWS CloudFormation templates.
// It extracts infrastructure components, security configurations, and relationships
// from CloudFormation YAML and JSON templates to build comprehensive threat models.
// The parser uses AWS Labs' GoFormation library for robust template parsing.
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

// Parser implements the ai.IaCParser interface for CloudFormation templates.
// It supports both JSON and YAML formats and can parse AWS resources including
// EC2 instances, RDS databases, S3 buckets, Lambda functions, and IAM roles.
// The parser also tracks security-sensitive parameters and outputs.
type Parser struct{}

// NewParser creates a new CloudFormation parser instance.
// The parser uses AWS Labs' GoFormation v7 library which provides
// comprehensive support for all CloudFormation resource types and
// intrinsic functions.
func NewParser() *Parser {
	return &Parser{}
}

// SupportsFile checks if the parser should attempt to parse the given file.
// CloudFormation templates can have various naming conventions, so this method
// uses a combination of file extensions and naming patterns to identify them.
//
// Supported patterns:
//   - File extensions: .yaml, .yml, .json
//   - Naming patterns: *template*, *stack*, *cloudformation*, *cfn*, cf-*
//   - Generic YAML/JSON files (validated during parsing)
//
// Parameters:
//   - filename: The path to the file to check
//
// Returns:
//   - true if the file might be a CloudFormation template, false otherwise
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

// ParseFile parses a CloudFormation template and extracts infrastructure components
// for threat modeling analysis. This method handles both JSON and YAML formats
// and uses GoFormation for accurate parsing of all AWS resource types.
//
// The parsing process:
//   1. Attempts to parse as JSON first, then YAML if JSON fails
//   2. Validates that the content is a valid CloudFormation template
//   3. Processes all resources, grouping them by security-relevant categories
//   4. Extracts parameters and outputs that may contain sensitive information
//   5. Maps AWS resources to threat model components
//
// Parameters:
//   - filename: The path to the file being parsed (for error reporting)
//   - content: The raw byte content of the CloudFormation template
//
// Returns:
//   - *ai.ParseResult: Structured data about discovered AWS infrastructure
//   - error: Parsing or validation errors
func (p *Parser) ParseFile(filename string, content []byte) (*ai.ParseResult, error) {
	// Initialize result structure with maps for each AWS resource category
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
	// GoFormation handles intrinsic functions, conditions, and references
	template, err := goformation.ParseJSON(content)
	if err != nil {
		// CloudFormation supports both JSON and YAML formats
		// Many users prefer YAML for its readability and comment support
		template, err = goformation.ParseYAML(content)
		if err != nil {
			// Validate this is actually a CloudFormation template
			// and not some other YAML/JSON file
			if !p.isCloudFormationTemplate(content) {
				return nil, fmt.Errorf("file does not appear to be a CloudFormation template")
			}
			return nil, fmt.Errorf("failed to parse CloudFormation template: %w", err)
		}
	}

	// Process all resources defined in the template
	// Each resource represents an AWS service that needs threat modeling
	for name, resource := range template.Resources {
		p.processResource(name, resource, result)
	}

	// Process parameters to identify sensitive inputs
	// Parameters marked with NoEcho may contain passwords or secrets
	if template.Parameters != nil {
		p.processParameters(template.Parameters, result)
	}

	// Process outputs to identify potentially exposed sensitive data
	// Outputs may expose resource attributes like database endpoints
	if template.Outputs != nil {
		p.processOutputs(template.Outputs, result)
	}

	return result, nil
}

// isCloudFormationTemplate validates whether the given content is a CloudFormation template.
// This method performs a quick check for CloudFormation-specific keys to distinguish
// CloudFormation templates from other YAML/JSON files.
//
// CloudFormation templates must contain at least one of:
//   - Resources section (required for all valid templates)
//   - AWSTemplateFormatVersion declaration
//
// Parameters:
//   - content: The raw file content to validate
//
// Returns:
//   - true if the content appears to be a CloudFormation template
func (p *Parser) isCloudFormationTemplate(content []byte) bool {
	// Try to unmarshal as JSON first (CloudFormation originally used JSON)
	var jsonData map[string]interface{}
	if err := json.Unmarshal(content, &jsonData); err == nil {
		// Check for CloudFormation-specific top-level keys
		if _, hasResources := jsonData["Resources"]; hasResources {
			return true
		}
		if _, hasAWSVersion := jsonData["AWSTemplateFormatVersion"]; hasAWSVersion {
			return true
		}
	}

	// Try YAML format (increasingly popular for CloudFormation due to readability)
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(content, &yamlData); err == nil {
		// Check for CloudFormation-specific top-level keys
		if _, hasResources := yamlData["Resources"]; hasResources {
			return true
		}
		if _, hasAWSVersion := yamlData["AWSTemplateFormatVersion"]; hasAWSVersion {
			return true
		}
	}

	return false
}

// processResource analyzes a CloudFormation resource and categorizes it for threat modeling.
// This method maps AWS resource types to security-relevant categories and extracts
// important attributes like tags, encryption settings, and network configurations.
//
// The method handles all major AWS resource types including:
//   - Compute (EC2, Lambda, ECS)
//   - Storage (S3, EFS, EBS)
//   - Database (RDS, DynamoDB, ElastiCache)
//   - Network (VPC, Security Groups, Load Balancers)
//   - IAM (Users, Roles, Policies)
//   - Messaging (SQS, SNS)
//
// Parameters:
//   - name: The logical name of the resource in the template
//   - resource: The CloudFormation resource object from GoFormation
//   - result: The ParseResult to populate with categorized resources
func (p *Parser) processResource(name string, resource cloudformation.Resource, result *ai.ParseResult) {
	resourceType := resource.AWSCloudFormationType()
	resourceID := name

	switch resourceType {
	// Compute resources - EC2 instances are primary compute resources
	// Important for threat modeling: instance metadata access, IMDSv2, user data scripts
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
	// This ensures we don't miss any resources that might be security-relevant
	// but aren't explicitly handled above (e.g., new AWS services)
	default:
		// Capture as generic resource to maintain visibility
		result.Resources[resourceID] = &ai.Resource{
			ID:       resourceID,
			Name:     name,
			Type:     "generic",
			Provider: "aws",
			Tags:     p.extractTags(resource),
		}
	}
}

// processParameters analyzes CloudFormation template parameters for security implications.
// Parameters are template inputs that can be provided at stack creation time.
// This method identifies potentially sensitive parameters based on naming conventions
// and CloudFormation NoEcho settings.
//
// Security considerations:
//   - Parameters with NoEcho=true hide values in CloudFormation console/API
//   - Common patterns like "Password", "Secret", "Key" indicate sensitive data
//   - These parameters need special handling in threat models
//
// Parameters:
//   - parameters: Map of parameter definitions from the template
//   - result: The ParseResult to update with parameter metadata
func (p *Parser) processParameters(parameters map[string]interface{}, result *ai.ParseResult) {
	if result.Metadata.Parameters == nil {
		result.Metadata.Parameters = make(map[string]interface{})
	}
	
	for name, param := range parameters {
		result.Metadata.Parameters[name] = param
		
		// Identify parameters likely to contain sensitive data
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

// processOutputs analyzes CloudFormation template outputs for security implications.
// Outputs are values that can be exported from a stack for use by other stacks
// or displayed in the CloudFormation console. They may inadvertently expose
// sensitive information.
//
// Security considerations:
//   - Outputs might expose internal endpoints, resource IDs, or ARNs
//   - Database connection strings or API endpoints could be leaked
//   - Exported values can be imported by any stack in the same account/region
//
// Parameters:
//   - outputs: Map of output definitions from the template
//   - result: The ParseResult to update with output metadata
func (p *Parser) processOutputs(outputs map[string]interface{}, result *ai.ParseResult) {
	if result.Metadata.Outputs == nil {
		result.Metadata.Outputs = make(map[string]interface{})
	}
	
	for name, output := range outputs {
		result.Metadata.Outputs[name] = output
		
		// Flag outputs that might expose sensitive information
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
// These methods handle the diverse property structures across different AWS resource types

// extractTags retrieves resource tags which are crucial for threat modeling.
// Tags often indicate:
//   - Environment (Production/Development/Staging)
//   - Data classification (Confidential/Public)
//   - Compliance requirements (PCI/HIPAA/SOC2)
//   - Cost center and ownership
//   - Backup and retention policies
//
// Parameters:
//   - resource: The CloudFormation resource to extract tags from
//
// Returns:
//   - Map of tag key-value pairs
//
// TODO: Implement tag extraction using GoFormation's resource-specific types
func (p *Parser) extractTags(resource cloudformation.Resource) map[string]string {
	tags := make(map[string]string)
	
	// Implementation would use type assertions to access Tags property
	// which varies by resource type in GoFormation
	return tags
}

// extractDescription retrieves the description property from IAM resources.
// Descriptions help understand the purpose and permissions of roles and policies,
// which is essential for identifying overly permissive configurations.
//
// Parameters:
//   - resource: The CloudFormation resource (typically IAM Role or Policy)
//
// Returns:
//   - Description string if available
//
// TODO: Implement using GoFormation IAM type assertions
func (p *Parser) extractDescription(resource cloudformation.Resource) string {
	// Would use type assertions for IAM resources to access Description field
	return ""
}

// extractSecurityRules parses ingress and egress rules from EC2 Security Groups.
// Security group rules are critical for threat modeling as they define:
//   - Network access controls
//   - Allowed protocols and ports
//   - Source/destination restrictions
//   - Potential attack vectors
//
// Common security issues to detect:
//   - Overly permissive rules (0.0.0.0/0)
//   - Unnecessary open ports
//   - Missing egress restrictions
//
// Parameters:
//   - resource: The SecurityGroup CloudFormation resource
//
// Returns:
//   - Slice of parsed security rules
//
// TODO: Implement using GoFormation's SecurityGroup types
func (p *Parser) extractSecurityRules(resource cloudformation.Resource) []ai.SecurityRule {
	rules := []ai.SecurityRule{}
	
	// Would parse SecurityGroupIngress and SecurityGroupEgress properties
	return rules
}

// extractRuntime identifies the runtime environment for Lambda functions.
// Runtime information is critical for security analysis:
//   - Identifies programming language and version
//   - Determines available security features
//   - Indicates potential vulnerabilities (outdated runtimes)
//   - Affects available AWS SDK versions
//
// Common runtimes: python3.9, nodejs18.x, java11, go1.x, dotnet6
//
// Parameters:
//   - resource: The Lambda Function CloudFormation resource
//
// Returns:
//   - Runtime identifier string
//
// TODO: Implement using GoFormation Lambda Function type
func (p *Parser) extractRuntime(resource cloudformation.Resource) string {
	// Would access Runtime property from Lambda::Function resource
	return ""
}

// extractContainerImage retrieves the Docker image from ECS task definitions.
// Container images are security-critical as they may contain:
//   - Vulnerable base images
//   - Hardcoded secrets
//   - Malicious code
//   - Outdated dependencies
//
// Image sources to validate:
//   - Public registries (Docker Hub) - higher risk
//   - ECR private registries - organization controlled
//   - Third-party registries - verify trust
//
// Parameters:
//   - resource: The ECS TaskDefinition CloudFormation resource
//
// Returns:
//   - Full container image URI including tag
//
// TODO: Implement using GoFormation ECS TaskDefinition type
func (p *Parser) extractContainerImage(resource cloudformation.Resource) string {
	// Would parse ContainerDefinitions[].Image from TaskDefinition
	return ""
}

// isSensitiveParameter determines if a parameter name suggests sensitive content.
// This heuristic-based approach identifies parameters that likely contain
// credentials, keys, or other sensitive data that requires special protection.
//
// Detection is based on common naming patterns for sensitive data:
//   - Passwords and secrets
//   - API keys and tokens
//   - Certificates and private keys
//   - Authentication credentials
//
// Parameters:
//   - name: The parameter name to check
//
// Returns:
//   - true if the parameter name suggests sensitive content
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

// isSensitiveOutput determines if an output name suggests sensitive content.
// Uses the same heuristic approach as parameter checking since outputs
// can expose the same types of sensitive data.
//
// Parameters:
//   - name: The output name to check
//
// Returns:
//   - true if the output name suggests sensitive content
func (p *Parser) isSensitiveOutput(name string) bool {
	return p.isSensitiveParameter(name) // Reuse parameter sensitivity logic
}

// ToThreagileModel converts AWS CloudFormation resources into Threagile's threat model format.
// This transformation is crucial for enabling threat analysis on cloud infrastructure.
//
// The conversion process:
//   1. Maps AWS resource types to Threagile technical asset types
//   2. Preserves security-relevant metadata and tags
//   3. Creates trust boundaries from VPC configurations
//   4. Maintains relationships for communication flow analysis
//
// Asset type mappings:
//   - EC2/Lambda/ECS → "process" (compute resources)
//   - RDS/DynamoDB/S3 → "datastore" (data persistence)
//   - ALB/NLB → "load-balancer" (traffic distribution)
//   - API Gateway → "gateway" (API endpoints)
//   - VPCs → Trust boundaries (network isolation)
//
// Parameters:
//   - result: The ParseResult containing categorized AWS resources
//
// Returns:
//   - *types.Model: Threagile model ready for threat analysis
//   - error: Any conversion errors
func (p *Parser) ToThreagileModel(result *ai.ParseResult) (*types.Model, error) {
	model := &types.Model{
		TechnicalAssets: make(map[string]*types.TechnicalAsset),
		DataAssets:      make(map[string]*types.DataAsset),
		TrustBoundaries: make(map[string]*types.TrustBoundary),
	}

	// Convert compute and API resources
	// These represent active processing components that handle data
	for id, resource := range result.Resources {
		// API Gateways get special treatment as entry points
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

	// Create trust boundaries from VPC configurations
	// VPCs provide network isolation and are fundamental security boundaries
	// in AWS cloud architecture
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

// convertTags transforms AWS resource tags to Threagile's tag format.
// Tags are preserved as they contain critical metadata for threat modeling
// such as environment classification, data sensitivity, and compliance scope.
//
// Parameters:
//   - tags: Map of AWS tag keys to values
//
// Returns:
//   - Slice of formatted tags in "key:value" format
func convertTags(tags map[string]string) []string {
	result := make([]string, 0, len(tags))
	for k, v := range tags {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
	}
	return result
}

// RegisterParser registers the CloudFormation parser with the AI orchestrator's registry.
// This enables automatic detection and parsing of CloudFormation templates during
// infrastructure analysis.
//
// The parser is registered with the name "cloudformation" and will be selected for:
//   - Files with CloudFormation naming patterns (template, stack, cfn)
//   - YAML/JSON files that contain CloudFormation structure
//   - Both JSON and YAML CloudFormation formats
//
// Parameters:
//   - registry: The parser registry to register with
//
// Returns:
//   - error: Registration error if the parser name is already taken
func RegisterParser(registry *ai.ParserRegistry) error {
	parser := NewParser()
	return registry.Register("cloudformation", parser)
}