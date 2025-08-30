package terraform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/types"
	"github.com/threagile/threagile/pkg/utils"
)

// Parser implements the ai.Parser interface for Terraform files
type Parser struct{}

// NewParser creates a new Terraform parser
func NewParser() *Parser {
	return &Parser{}
}

// Name returns the parser name
func (p *Parser) Name() string {
	return "terraform"
}

// SupportedExtensions returns file extensions this parser handles
func (p *Parser) SupportedExtensions() []string {
	return []string{".tf", ".tf.json", ".tfvars", ".tfvars.json"}
}

// Parse analyzes Terraform files and extracts infrastructure components
func (p *Parser) Parse(files []string) (*ai.ParseResult, error) {
	result := &ai.ParseResult{
		TechnicalAssets: []ai.TechnicalAsset{},
		TrustBoundaries: []ai.TrustBoundary{},
		Communications:  []ai.CommunicationLink{},
		DataAssets:      []ai.DataAsset{},
		Metadata: map[string]interface{}{
			"parser": "terraform",
			"files":  len(files),
		},
	}

	// Parse each file
	for _, file := range files {
		if err := p.parseFile(file, result); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
	}

	// Post-process to detect relationships
	p.detectCommunications(result)
	p.suggestTrustBoundaries(result)

	return result, nil
}

// parseFile parses a single Terraform file
func (p *Parser) parseFile(filePath string, result *ai.ParseResult) error {
	// For MVP, we'll do simple pattern matching
	// In future phases, use HCL parser for full AST analysis
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Parse resources using simple pattern matching
	lines := strings.Split(string(content), "\n")
	var currentResource *resourceBlock
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Detect resource blocks
		if strings.HasPrefix(line, "resource \"") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				resourceType := strings.Trim(parts[1], "\"")
				resourceName := strings.Trim(parts[2], "\"")
				currentResource = &resourceBlock{
					Type: resourceType,
					Name: resourceName,
					Properties: make(map[string]interface{}),
				}
			}
		}
		
		// Detect end of resource block and process the resource
		if line == "}" && currentResource != nil {
			// Process the completed resource based on its type
			switch currentResource.Type {
			case "aws_vpc":
				asset := p.vpcToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
				// VPC creates a trust boundary
				boundary := ai.TrustBoundary{
					ID:    "vpc_" + utils.SanitizeID(currentResource.Name),
					Title: "VPC " + currentResource.Name,
					Type:  ai.BoundaryTypeVPC,
					Properties: map[string]interface{}{
						"resource": currentResource.Type,
					},
				}
				result.TrustBoundaries = append(result.TrustBoundaries, boundary)
				
			case "aws_instance":
				asset := p.ec2ToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
			case "aws_db_instance":
				asset := p.rdsToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
				// Add generic data asset
				dataAsset := ai.DataAsset{
					ID:    "data_" + utils.SanitizeID(currentResource.Name),
					Title: "Database Data",
					Classification: types.Confidential,
					Quantity: types.Many,
				}
				result.DataAssets = append(result.DataAssets, dataAsset)
				
			case "aws_s3_bucket":
				asset := p.s3ToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
				// Add data asset for bucket
				dataAsset := ai.DataAsset{
					ID:    "data_s3_" + utils.SanitizeID(currentResource.Name),
					Title: "S3 Bucket Data",
					Classification: types.Confidential,
					Quantity: types.VeryMany,
				}
				result.DataAssets = append(result.DataAssets, dataAsset)
				
			case "aws_lambda_function":
				asset := p.lambdaToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
			case "aws_lb", "aws_alb", "aws_elb":
				asset := p.loadBalancerToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
			}
			
			// Also check for RDS variants
			if strings.HasPrefix(currentResource.Type, "aws_db_") && currentResource.Type != "aws_db_instance" {
				asset := p.rdsToAsset(currentResource, filePath)
				result.TechnicalAssets = append(result.TechnicalAssets, asset)
				
				// Add generic data asset
				dataAsset := ai.DataAsset{
					ID:    "data_" + utils.SanitizeID(currentResource.Name),
					Title: "Database Data",
					Classification: types.Confidential,
					Quantity: types.Many,
				}
				result.DataAssets = append(result.DataAssets, dataAsset)
			}
			
			currentResource = nil
		}
	}
	
	return nil
}

// Resource conversion helpers

func (p *Parser) vpcToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "vpc_" + utils.SanitizeID(resource.Name),
		Title:      "VPC " + resource.Name,
		Type:       ai.AssetTypeNetwork,
		Technology: types.Technology{Name: types.Gateway},
		Machine:    types.Virtual,
		Internet:   false,
		Encryption: types.Transparent,
		Tags:       []string{"terraform", "aws", "vpc"},
		IACSource:  filepath.Base(sourceFile),
		Properties: map[string]interface{}{
			"vpc": resource.Name,
		},
	}
}

func (p *Parser) ec2ToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "ec2_" + utils.SanitizeID(resource.Name),
		Title:      "EC2 " + resource.Name,
		Type:       ai.AssetTypeCompute,
		Technology: types.Technology{Name: types.UnknownTechnology},
		Machine:    types.Virtual,
		Internet:   false, // Would need to check security groups
		Encryption: types.NoneEncryption,
		Tags:       []string{"terraform", "aws", "ec2"},
		IACSource:  filepath.Base(sourceFile),
		Properties: resource.Properties,
	}
}

func (p *Parser) rdsToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "rds_" + utils.SanitizeID(resource.Name),
		Title:      "RDS " + resource.Name,
		Type:       ai.AssetTypeDatabase,
		Technology: types.Technology{Name: types.Database},
		Machine:    types.Virtual,
		Internet:   false,
		Encryption: types.DataWithSymmetricSharedKey,
		Tags:       []string{"terraform", "aws", "rds", "database"},
		IACSource:  filepath.Base(sourceFile),
		Properties: resource.Properties,
	}
}

func (p *Parser) s3ToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "s3_" + utils.SanitizeID(resource.Name),
		Title:      "S3 " + resource.Name,
		Type:       ai.AssetTypeStorage,
		Technology: types.Technology{Name: types.FileServer},
		Machine:    types.Serverless,
		Internet:   true, // S3 is internet-facing by default
		Encryption: types.DataWithSymmetricSharedKey,
		Tags:       []string{"terraform", "aws", "s3", "storage"},
		IACSource:  filepath.Base(sourceFile),
		Properties: resource.Properties,
	}
}

func (p *Parser) lambdaToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "lambda_" + utils.SanitizeID(resource.Name),
		Title:      "Lambda " + resource.Name,
		Type:       ai.AssetTypeServerless,
		Technology: types.Technology{Name: types.Task},
		Machine:    types.Serverless,
		Internet:   false,
		Encryption: types.NoneEncryption,
		Tags:       []string{"terraform", "aws", "lambda", "serverless"},
		IACSource:  filepath.Base(sourceFile),
		Properties: resource.Properties,
	}
}

func (p *Parser) loadBalancerToAsset(resource *resourceBlock, sourceFile string) ai.TechnicalAsset {
	return ai.TechnicalAsset{
		ID:         "lb_" + utils.SanitizeID(resource.Name),
		Title:      "Load Balancer " + resource.Name,
		Type:       ai.AssetTypeLoadBalancer,
		Technology: types.Technology{Name: types.LoadBalancer},
		Machine:    types.Virtual,
		Internet:   true, // ALBs are typically internet-facing
		Encryption: types.DataWithAsymmetricSharedKey,
		Tags:       []string{"terraform", "aws", "loadbalancer"},
		IACSource:  filepath.Base(sourceFile),
		Properties: resource.Properties,
	}
}

// detectCommunications infers communication links between assets
func (p *Parser) detectCommunications(result *ai.ParseResult) {
	// Simple heuristics for MVP
	
	// Load balancers communicate with EC2 instances
	for _, asset := range result.TechnicalAssets {
		if asset.Type == ai.AssetTypeLoadBalancer {
			for _, target := range result.TechnicalAssets {
				if target.Type == ai.AssetTypeCompute {
					comm := ai.CommunicationLink{
						ID:       fmt.Sprintf("comm_%s_to_%s", asset.ID, target.ID),
						SourceID: asset.ID,
						TargetID: target.ID,
						Title:    "HTTP Traffic",
						Protocol: types.HTTPS,
						Encryption: types.DataWithAsymmetricSharedKey,
						Authentication: types.ClientCertificate,
					}
					result.Communications = append(result.Communications, comm)
				}
			}
		}
		
		// EC2 instances communicate with databases
		if asset.Type == ai.AssetTypeCompute {
			for _, target := range result.TechnicalAssets {
				if target.Type == ai.AssetTypeDatabase {
					comm := ai.CommunicationLink{
						ID:       fmt.Sprintf("comm_%s_to_%s", asset.ID, target.ID),
						SourceID: asset.ID,
						TargetID: target.ID,
						Title:    "Database Connection",
						Protocol: types.SqlAccessProtocol,
						Encryption: types.DataWithAsymmetricSharedKey,
						Authentication: types.Credentials,
						DataAssets: []string{"data_" + strings.TrimPrefix(target.ID, "rds_")},
					}
					result.Communications = append(result.Communications, comm)
				}
			}
		}
		
		// Lambda functions may access S3 buckets
		if asset.Type == ai.AssetTypeServerless {
			for _, target := range result.TechnicalAssets {
				if target.Type == ai.AssetTypeStorage {
					comm := ai.CommunicationLink{
						ID:       fmt.Sprintf("comm_%s_to_%s", asset.ID, target.ID),
						SourceID: asset.ID,
						TargetID: target.ID,
						Title:    "S3 Access",
						Protocol: types.HTTPS,
						Encryption: types.DataWithAsymmetricSharedKey,
						Authentication: types.Token,
						DataAssets: []string{"data_" + strings.TrimPrefix(target.ID, "s3_")},
					}
					result.Communications = append(result.Communications, comm)
				}
			}
		}
	}
}

// suggestTrustBoundaries adds trust boundaries based on network topology
func (p *Parser) suggestTrustBoundaries(result *ai.ParseResult) {
	// Group assets by VPC if not already bounded
	vpcAssets := make(map[string][]string)
	
	for _, asset := range result.TechnicalAssets {
		if vpc, ok := asset.Properties["vpc"].(string); ok {
			vpcAssets[vpc] = append(vpcAssets[vpc], asset.ID)
		}
	}
	
	// Update trust boundaries with asset assignments
	for _, boundary := range result.TrustBoundaries {
		if strings.HasPrefix(boundary.ID, "vpc_") {
			vpcName := strings.TrimPrefix(boundary.ID, "vpc_")
			if assets, ok := vpcAssets[vpcName]; ok {
				boundary.Assets = assets
			}
		}
	}
	
	// Create default boundary for unbounded assets
	unboundedAssets := []string{}
	for _, asset := range result.TechnicalAssets {
		bounded := false
		for _, boundary := range result.TrustBoundaries {
			for _, id := range boundary.Assets {
				if id == asset.ID {
					bounded = true
					break
				}
			}
			if bounded {
				break
			}
		}
		if !bounded {
			unboundedAssets = append(unboundedAssets, asset.ID)
		}
	}
	
	if len(unboundedAssets) > 0 {
		defaultBoundary := ai.TrustBoundary{
			ID:    "default_network",
			Title: "Default Network",
			Type:  ai.BoundaryTypeNetwork,
			Assets: unboundedAssets,
		}
		result.TrustBoundaries = append(result.TrustBoundaries, defaultBoundary)
	}
}

// Helper types

type resourceBlock struct {
	Type       string
	Name       string
	Properties map[string]interface{}
}

// RegisterParser registers the Terraform parser with the AI registry
func RegisterParser(registry ai.ParserRegistry) error {
	return registry.Register(NewParser())
}