# HCL Parser Research for Threagile Project

## Executive Summary

This research evaluates HashiCorp Configuration Language (HCL) parsing libraries suitable for integration into the Threagile threat modeling toolkit. The goal is to enable Threagile to parse Terraform files and extract infrastructure components for automated threat model generation from Infrastructure as Code (IaC) definitions.

**Key Findings:**
- **Recommended Solution**: HashiCorp HCL v2 (`github.com/hashicorp/hcl/v2`)
- **License Compatibility**: All evaluated libraries are compatible with Threagile's MIT license
- **Performance**: Official HCL v2 library provides best balance of features, performance, and maintainability
- **Use Case Alignment**: HCL v2 offers the most comprehensive Terraform parsing capabilities needed for security analysis

## Research Methodology

- **Scope**: 15 web searches and detailed analysis of official documentation
- **Focus Areas**: Official libraries, third-party alternatives, security tools usage, licensing, performance
- **Primary Sources**: HashiCorp official documentation, GitHub repositories, Go package documentation
- **Search Strategy**: Started with official HashiCorp libraries, expanded to alternatives and real-world usage

## Key Findings

### 1. **HashiCorp HCL v2 (Official) - RECOMMENDED**

**Repository**: `github.com/hashicorp/hcl/v2`  
**License**: Mozilla Public License 2.0 (MPL-2.0)  
**Maturity**: Production-ready, actively maintained by HashiCorp

#### Features & Capabilities
- **Comprehensive Parsing**: Supports both native HCL syntax and JSON variants
- **Expression Support**: Handles complex expressions, variables, and function calls
- **Multiple APIs**: Provides high-level (`hclsimple`) and low-level (`hclsyntax`) APIs
- **Error Handling**: Robust error reporting and diagnostics
- **Write Support**: Can both parse and generate HCL files via `hclwrite`

#### API Structure
```go
// High-level simple API
import "github.com/hashicorp/hcl/v2/hclsimple"

// Main parsing API
import "github.com/hashicorp/hcl/v2/hclparse"

// Go integration helpers
import "github.com/hashicorp/hcl/v2/gohcl"

// Low-level syntax handling
import "github.com/hashicorp/hcl/v2/hclsyntax"

// Writing/modifying HCL
import "github.com/hashicorp/hcl/v2/hclwrite"
```

#### Code Example - Basic Terraform Parsing
```go
package main

import (
    "fmt"
    "github.com/hashicorp/hcl/v2"
    "github.com/hashicorp/hcl/v2/hclparse"
    "github.com/hashicorp/hcl/v2/gohcl"
)

type Config struct {
    Resources []Resource `hcl:"resource,block"`
    Variables []Variable `hcl:"variable,block"`
}

type Resource struct {
    Type string `hcl:"type,label"`
    Name string `hcl:"name,label"`
    Body hcl.Body `hcl:",remain"`
}

type Variable struct {
    Name        string `hcl:"name,label"`
    Default     *string `hcl:"default,optional"`
    Description *string `hcl:"description,optional"`
}

func main() {
    parser := hclparse.NewParser()
    file, diags := parser.ParseHCLFile("main.tf")
    if diags.HasErrors() {
        fmt.Printf("Parse errors: %s\n", diags.Error())
        return
    }

    var config Config
    diags = gohcl.DecodeBody(file.Body, nil, &config)
    if diags.HasErrors() {
        fmt.Printf("Decode errors: %s\n", diags.Error())
        return
    }

    fmt.Printf("Found %d resources and %d variables\n", 
        len(config.Resources), len(config.Variables))
}
```

#### Pros
- ✅ **Official Support**: Maintained by HashiCorp, guaranteed compatibility
- ✅ **Feature Complete**: Supports all HCL features including expressions
- ✅ **Production Ready**: Used by Terraform, Vault, Nomad, and other HashiCorp tools
- ✅ **Excellent Documentation**: Comprehensive API documentation and examples
- ✅ **Active Development**: Regular updates and bug fixes
- ✅ **Diagnostic Support**: Detailed error messages with source location information
- ✅ **Bidirectional**: Can both parse and generate HCL files

#### Cons
- ❌ **Complexity**: Lower-level API can be complex for simple use cases
- ❌ **Learning Curve**: Requires understanding of HCL's evaluation model
- ❌ **Size**: Larger dependency footprint compared to simpler parsers

### 2. **Third-Party HCL Parser Go**

**Repository**: `github.com/joselitofilho/hcl-parser-go`  
**License**: MIT License  
**Maturity**: Community-maintained, 90.4% test coverage

#### Features & Capabilities
- **Terraform-Focused**: Specifically designed for Terraform HCL parsing
- **Simple API**: Straightforward extraction of resources, modules, variables, locals
- **Lightweight**: Minimal dependencies and focused scope

#### Code Example
```go
package main

import (
    "fmt"
    "github.com/joselitofilho/hcl-parser-go"
)

func main() {
    directories := []string{}
    files := []string{"main.tf", "variables.tf"}
    
    config, err := hcl.Parse(directories, files)
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        return
    }
    
    // Access parsed resources, variables, etc.
    for _, resource := range config.Resources {
        fmt.Printf("Resource: %s.%s\n", resource.Type, resource.Name)
    }
}
```

#### Pros
- ✅ **Simplicity**: Easy to use API for basic Terraform parsing
- ✅ **MIT License**: Very permissive licensing
- ✅ **Focused**: Designed specifically for Terraform use cases
- ✅ **Good Coverage**: High test coverage (90.4%)

#### Cons
- ❌ **Limited Scope**: May not handle complex HCL expressions
- ❌ **Community Support**: Single maintainer, less guaranteed longevity
- ❌ **Feature Gaps**: Likely missing advanced HCL features
- ❌ **Documentation**: Less comprehensive documentation than official library

### 3. **Terraform Config Inspect**

**Repository**: `github.com/hashicorp/terraform-config-inspect/tfconfig`  
**License**: Mozilla Public License 2.0 (MPL-2.0)  
**Maturity**: Official HashiCorp library, focused on metadata extraction

#### Features & Capabilities
- **Metadata Focus**: Extracts high-level module metadata without full evaluation
- **Shallow Parsing**: Performs "careful, shallow parsing" of Terraform modules
- **Broad Compatibility**: Works with configurations targeting various Terraform versions
- **Best Effort**: Designed to produce complete results even with potentially invalid input

#### Code Example
```go
package main

import (
    "fmt"
    "github.com/hashicorp/terraform-config-inspect/tfconfig"
)

func main() {
    module, diags := tfconfig.LoadModule("./terraform-configs")
    if diags.HasErrors() {
        fmt.Printf("Load errors: %s\n", diags.Error())
        return
    }

    fmt.Printf("Module: %s\n", module.Path)
    fmt.Printf("Variables: %d\n", len(module.Variables))
    fmt.Printf("Outputs: %d\n", len(module.Outputs))
    fmt.Printf("Resources: %d\n", len(module.ManagedResources))
    
    for _, resource := range module.ManagedResources {
        fmt.Printf("  Resource: %s\n", resource.Type)
    }
}
```

#### Pros
- ✅ **Official HashiCorp**: Maintained by HashiCorp team
- ✅ **Metadata Focus**: Perfect for extracting high-level information
- ✅ **Robust**: Handles partially invalid configurations gracefully
- ✅ **Fast**: Optimized for quick metadata extraction without full evaluation

#### Cons
- ❌ **Limited Depth**: Cannot access detailed resource configurations
- ❌ **No Expression Evaluation**: Does not resolve variables or expressions
- ❌ **Metadata Only**: Not suitable for deep configuration analysis

### 4. **Alec Thomas HCL Parser**

**Repository**: `github.com/alecthomas/hcl`  
**License**: MIT License  
**Maturity**: Community-maintained, HCL1 compatible

#### Features & Capabilities
- **HCL1 Compatible**: Supports HCL version 1 syntax only
- **Go Integration**: Native support for `time.Duration`, `time.Time`, and unmarshaling interfaces
- **Simplicity**: Much less complex than official `gohcl` package
- **AST Support**: Provides Abstract Syntax Tree for advanced use cases

#### Code Example
```go
package main

import (
    "github.com/alecthomas/hcl"
)

type Config struct {
    Database struct {
        Host string `hcl:"host"`
        Port int    `hcl:"port"`
    } `hcl:"database"`
}

func main() {
    var config Config
    err := hcl.Unmarshal([]byte(`
        database {
            host = "localhost"
            port = 5432
        }
    `), &config)
    
    if err != nil {
        panic(err)
    }
}
```

#### Pros
- ✅ **Simple API**: Very straightforward marshaling/unmarshaling
- ✅ **Extended Types**: Native support for time types and unmarshaling interfaces
- ✅ **MIT License**: Very permissive licensing
- ✅ **Lightweight**: Minimal complexity and dependencies

#### Cons
- ❌ **HCL1 Only**: No support for HCL2 features (expressions, functions)
- ❌ **Limited Terraform Support**: Cannot handle modern Terraform configurations
- ❌ **Community Maintained**: Single maintainer, less guaranteed support

## Performance Comparison

While specific benchmarks were not available in public sources, the analysis reveals:

### Memory Efficiency
- **HCL v2**: Implements parser caching - "retains a registry of all files parsed so that multiple attempts to parse the same file will return the same object"
- **Third-party parsers**: Generally have smaller memory footprint but may lack optimization features

### Parsing Speed
- **HCL v2**: Optimized for production use in Terraform and other HashiCorp tools
- **terraform-config-inspect**: Optimized specifically for fast metadata extraction
- **Community parsers**: May be faster for simple use cases but lack comprehensive feature support

### Scalability
- **HCL v2**: Battle-tested in large-scale Terraform deployments
- **Third-party options**: Less proven at scale

## Security Analysis Tools Usage

Research into how security analysis tools use HCL parsers revealed:

### tfsec (now part of Trivy)
- **Parser Used**: "Deeply integrates with Terraform's official Hashicorp Configuration Language (HCL) parser"
- **Approach**: Uses official HCL parser to understand Terraform code contextually
- **Benefits**: "Enabling accurate scans with good coverage of all Terraform functions"

### Trivy
- **Integration**: "Now includes the Terraform HCL scanning system from tfsec"
- **Capabilities**: Reports misconfigurations, vulnerabilities, and hardcoded secrets in IaC code

### Checkov
- **Multi-format Support**: Scans Terraform along with other IaC formats
- **HCL Integration**: Uses HCL parsing to understand Terraform configurations for security analysis

**Key Insight**: Production security tools consistently choose the official HashiCorp HCL parser for accuracy and comprehensive feature support.

## License Compatibility Analysis

### Threagile License
- **License**: MIT License (confirmed from `/LICENSE.txt`)
- **Compatibility**: Highly permissive, compatible with most open-source licenses

### HCL Library Licenses
| Library | License | MIT Compatible | Notes |
|---------|---------|----------------|--------|
| hashicorp/hcl/v2 | MPL-2.0 | ✅ Yes | Copyleft but allows linking |
| joselitofilho/hcl-parser-go | MIT | ✅ Yes | Same license as Threagile |
| terraform-config-inspect | MPL-2.0 | ✅ Yes | Copyleft but allows linking |
| alecthomas/hcl | MIT | ✅ Yes | Same license as Threagile |

**Important Notes on MPL-2.0:**
- MPL-2.0 allows linking and distribution with MIT-licensed code
- Requires that modifications to MPL-2.0 files be shared under MPL-2.0
- Does not impose copyleft requirements on the larger work
- HashiCorp confirmed HCL remains MPL-2.0 even after their BSL license change for main products

## Real-World Usage Examples

### Parsing Terraform Resources for Security Analysis
```go
package main

import (
    "fmt"
    "github.com/hashicorp/hcl/v2"
    "github.com/hashicorp/hcl/v2/hclparse"
    "github.com/hashicorp/hcl/v2/gohcl"
)

// Terraform resource structure for security analysis
type TerraformConfig struct {
    Resources []TerraformResource `hcl:"resource,block"`
    DataSources []TerraformDataSource `hcl:"data,block"`
    Variables []TerraformVariable `hcl:"variable,block"`
    Outputs   []TerraformOutput   `hcl:"output,block"`
}

type TerraformResource struct {
    Type string   `hcl:"type,label"`
    Name string   `hcl:"name,label"`
    Config hcl.Body `hcl:",remain"`
}

type TerraformDataSource struct {
    Type string   `hcl:"type,label"`
    Name string   `hcl:"name,label"`
    Config hcl.Body `hcl:",remain"`
}

type TerraformVariable struct {
    Name        string  `hcl:"name,label"`
    Type        *string `hcl:"type,optional"`
    Description *string `hcl:"description,optional"`
    Default     hcl.Expression `hcl:"default,optional"`
    Sensitive   *bool   `hcl:"sensitive,optional"`
}

type TerraformOutput struct {
    Name        string         `hcl:"name,label"`
    Value       hcl.Expression `hcl:"value"`
    Description *string        `hcl:"description,optional"`
    Sensitive   *bool          `hcl:"sensitive,optional"`
}

func ParseTerraformFile(filename string) (*TerraformConfig, error) {
    parser := hclparse.NewParser()
    file, diags := parser.ParseHCLFile(filename)
    if diags.HasErrors() {
        return nil, fmt.Errorf("parse errors: %s", diags.Error())
    }

    var config TerraformConfig
    diags = gohcl.DecodeBody(file.Body, nil, &config)
    if diags.HasErrors() {
        return nil, fmt.Errorf("decode errors: %s", diags.Error())
    }

    return &config, nil
}

// Example: Extract security-relevant information
func AnalyzeSecurityImplications(config *TerraformConfig) {
    for _, resource := range config.Resources {
        switch resource.Type {
        case "aws_instance":
            fmt.Printf("Found EC2 instance: %s\n", resource.Name)
            // Analyze security groups, key pairs, etc.
            
        case "aws_s3_bucket":
            fmt.Printf("Found S3 bucket: %s\n", resource.Name)
            // Analyze bucket policies, encryption, public access
            
        case "aws_security_group":
            fmt.Printf("Found security group: %s\n", resource.Name)
            // Analyze ingress/egress rules
            
        case "aws_iam_role":
            fmt.Printf("Found IAM role: %s\n", resource.Name)
            // Analyze permissions and trust policies
        }
    }
    
    // Analyze variables for sensitive data exposure
    for _, variable := range config.Variables {
        if variable.Sensitive != nil && !*variable.Sensitive {
            fmt.Printf("Warning: Variable '%s' may contain sensitive data but not marked as sensitive\n", 
                variable.Name)
        }
    }
}
```

### Integration with Threagile Model Generation
```go
package main

import (
    "github.com/hashicorp/hcl/v2/hclparse"
    "github.com/hashicorp/hcl/v2/gohcl"
)

// Convert Terraform resources to Threagile technical assets
func ConvertToThreagileAssets(tfConfig *TerraformConfig) []TechnicalAsset {
    var assets []TechnicalAsset
    
    for _, resource := range tfConfig.Resources {
        asset := TechnicalAsset{
            ID: fmt.Sprintf("%s_%s", resource.Type, resource.Name),
            Title: generateAssetTitle(resource.Type, resource.Name),
            Type: mapTerraformTypeToThreagile(resource.Type),
            Usage: "business", // Default, could be inferred from context
            
            // Extract technology, protocols, data assets based on resource type
            Technologies: extractTechnologies(resource),
            Communication: extractCommunications(resource),
            DataAssetsProcessed: extractDataAssets(resource),
        }
        
        assets = append(assets, asset)
    }
    
    return assets
}

func mapTerraformTypeToThreagile(terraformType string) string {
    mapping := map[string]string{
        "aws_instance":       "process",
        "aws_lambda_function": "process",
        "aws_s3_bucket":      "datastore",
        "aws_rds_instance":   "datastore",
        "aws_alb":            "load-balancer",
        "aws_api_gateway":    "process",
        // ... more mappings
    }
    
    if threagileType, exists := mapping[terraformType]; exists {
        return threagileType
    }
    return "process" // Default
}
```

## Recommendation

### Primary Recommendation: HashiCorp HCL v2

**Rationale:**
1. **Official Support**: Maintained by HashiCorp, ensuring long-term compatibility and support
2. **Feature Completeness**: Handles all HCL features including expressions, functions, and complex configurations
3. **Production Proven**: Used by HashiCorp's own products and major security tools (tfsec, Trivy)
4. **Comprehensive API**: Offers both high-level simple APIs and low-level control when needed
5. **Active Development**: Regular updates and improvements from the HashiCorp team
6. **License Compatibility**: MPL-2.0 is fully compatible with Threagile's MIT license

### Implementation Strategy

#### Phase 1: Basic Resource Extraction
- Use `hclparse` for file parsing
- Use `gohcl` for structured decoding
- Focus on extracting resources, variables, and data sources

#### Phase 2: Advanced Configuration Analysis
- Implement expression evaluation for dynamic configurations
- Extract security-relevant attributes (security groups, IAM policies, etc.)
- Handle Terraform modules and variable interpolation

#### Phase 3: Deep Integration
- Use `hclwrite` for generating modified Terraform configurations with security improvements
- Implement comprehensive mapping from Terraform resources to Threagile technical assets
- Support for complex scenarios like multi-file projects and remote state

### Alternative Consideration

**For Simple Use Cases**: If Threagile only needs basic resource extraction without expression evaluation, the `terraform-config-inspect` library offers a simpler alternative that's still officially maintained by HashiCorp.

## Implementation Guidelines

### Dependency Management
```go
// go.mod
require (
    github.com/hashicorp/hcl/v2 v2.19.1
)
```

### Error Handling Best Practices
```go
func ParseWithErrorHandling(filename string) (*Config, error) {
    parser := hclparse.NewParser()
    file, diags := parser.ParseHCLFile(filename)
    
    // HCL uses diagnostics instead of simple errors
    if diags.HasErrors() {
        // Format diagnostics for user-friendly error messages
        return nil, fmt.Errorf("HCL parse errors:\n%s", diags.Error())
    }
    
    // Continue with decoding...
}
```

### Performance Optimization
```go
// Reuse parser instance for multiple files
parser := hclparse.NewParser()

// Parse multiple files with shared context
for _, filename := range filenames {
    file, diags := parser.ParseHCLFile(filename)
    // Parser automatically caches and reuses parsed files
}
```

## Conclusion

The HashiCorp HCL v2 library represents the best choice for integrating Terraform parsing capabilities into Threagile. Its comprehensive feature set, official support, production-proven reliability, and compatible licensing make it the clear recommendation for this integration.

The library's complexity is justified by the comprehensive feature support needed for accurate security analysis of modern Terraform configurations. The investment in learning the more complex API will pay dividends in terms of accuracy, maintainability, and future-proofing the Threagile codebase.

---

**Research Completed**: August 30, 2025  
**Document Version**: 1.0  
**Next Steps**: Begin prototype implementation using HashiCorp HCL v2 with focus on basic resource extraction