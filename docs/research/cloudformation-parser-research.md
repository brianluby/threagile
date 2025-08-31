# CloudFormation Parser Research for Threagile Integration

## Executive Summary

This document provides comprehensive research on open-source CloudFormation parsers and libraries that could be integrated into Threagile for analyzing AWS infrastructure. The research covers parsing capabilities, security analysis tools, license compatibility, and implementation recommendations.

## Key Findings

1. **GoFormation** emerges as the most comprehensive Go-native CloudFormation parser with strong typing and AWS Labs backing
2. **Multiple security analysis tools** (cfn-guard, checkov, cfn-nag) provide security validation capabilities with different integration approaches
3. **License compatibility** is excellent across all major tools (Apache 2.0, MIT, BSD variants)
4. **Integration patterns** vary from direct library usage to subprocess execution depending on the tool's architecture

## 1. AWS SDK CloudFormation Parsing Capabilities

### AWS SDK for Go (Official)

**Repository**: `github.com/aws/aws-sdk-go-v2/service/cloudformation`
**License**: Apache-2.0
**Purpose**: CloudFormation service API interactions

The official AWS SDK for Go provides the cloudformation package with client and types for making API requests to AWS CloudFormation service. However, this is primarily designed for:
- Creating and managing CloudFormation stacks
- Retrieving stack information and events
- API-level interactions with the CloudFormation service

**Limitations**: Not designed for parsing CloudFormation template files directly.

### Rain CFN Parse Package

**Repository**: `github.com/aws-cloudformation/rain/cfn/parse`
**License**: Apache-2.0
**Purpose**: Lightweight CloudFormation template parsing

**Key Functions**:
```go
func File(fileName string) (cfn.Template, error)
func Reader(r io.Reader) (cfn.Template, error)  
func String(input string) (cfn.Template, error)
func Verify(source cfn.Template, output string) error
```

**Usage Example**:
```go
template, err := parse.String(`
Resources:
  Bucket:
    Type: AWS::S3::Bucket
`)
```

**Pros**:
- Simple, focused API for basic parsing needs
- Part of the official AWS CloudFormation toolkit
- Lightweight with minimal dependencies

**Cons**:
- Limited to basic parsing functionality
- Less comprehensive than specialized libraries

## 2. Third-Party CloudFormation Parsers for Go

### GoFormation (Recommended)

**Repository**: `github.com/awslabs/goformation`
**License**: Apache-2.0
**Maintainer**: AWS Labs
**Current Version**: v7

**Key Features**:
- Bidirectional conversion between CloudFormation templates and Go structs
- Strongly typed Go structs for every AWS CloudFormation and SAM resource
- Automatically generated from AWS CloudFormation Resource Specification
- Support for CloudFormation intrinsic functions
- Active maintenance and regular updates

**Installation**:
```bash
go get github.com/awslabs/goformation/v7
```

**Usage Examples**:

*Marshalling (Go Structs to Template)*:
```go
template := cloudformation.NewTemplate()
template.Resources["MyTopic"] = &sns.Topic{
    TopicName: cloudformation.String("my-topic-" + timestamp),
}
```

*Unmarshalling (Template to Go Structs)*:
```go
template, err := goformation.Open("template.yaml")
functions := template.GetAllServerlessFunctionResources()
```

**Supported Intrinsic Functions**:
- `Ref`
- `Fn::Base64`, `Fn::FindInMap`, `Fn::Join`, `Fn::Select`, `Fn::Sub`
- Conditional functions (`And`, `Equals`, `If`, `Not`, `Or`)

**Pros**:
- Most comprehensive Go library for CloudFormation
- Strong typing reduces errors
- Official AWS Labs support
- Regular updates based on AWS specifications
- Excellent documentation and examples

**Cons**:
- Larger dependency footprint
- More complex for simple parsing needs

### go-cloudformation (Archived)

**Repository**: `github.com/crewjam/go-cloudformation`
**License**: BSD-2-Clause
**Status**: Archived (Jan 3, 2022)

**Key Features**:
- Type-safe CloudFormation template handling
- Supports parsing and creating templates
- Converts CloudFormation resource names to Go struct names

**Usage Examples**:

*Parsing*:
```go
t := Template{}
json.NewDecoder(os.Stdin).Decode(&t)
fmt.Printf("DNS name: %s\n", t.Parameters["DnsName"].Default)
```

*Creating*:
```go
t := NewTemplate()
t.Parameters["DnsName"] = &Parameter{
    Type: "string",
    Default: "example.com",
    Description: "the top level DNS name for the service"
}
t.AddResource("DataBucket", &S3Bucket{
    BucketName: Join("-", String("data"), Ref("DnsName"))
})
```

**Pros**:
- BSD license provides maximum flexibility
- Type-safe approach

**Cons**:
- **Archived and unmaintained**
- Some types appear as `interface{}`
- Cumbersome scalar literal syntax
- Not recommended for new projects

### AWS CloudFormation Resource Schema SDK Go

**Repository**: `github.com/hashicorp/aws-cloudformation-resource-schema-sdk-go`
**License**: Apache-2.0
**Maintainer**: HashiCorp

**Key Features**:
- Validation of CloudFormation resource schema documents
- Parsing schema documents into native Go types
- Methods for interacting with resource schemas

**Use Case**: Primarily for CloudFormation custom resource providers rather than template parsing.

## 3. CloudFormation Template Validation Libraries

### cfn-lint

**Repository**: `github.com/aws-cloudformation/cfn-lint`
**Language**: Python
**License**: MIT-0
**Purpose**: CloudFormation template syntax and best practice validation

**Key Features**:
- Comprehensive CloudFormation template validation
- 400+ built-in rules
- Support for custom rules
- Integration with popular editors and CI/CD systems

**Go Integration**: Execute as subprocess using `os/exec`

**Example Integration**:
```go
import (
    "os/exec"
    "encoding/json"
)

func validateTemplate(templatePath string) error {
    cmd := exec.Command("cfn-lint", "--format", "json", templatePath)
    output, err := cmd.Output()
    if err != nil {
        return err
    }
    
    var results []ValidationResult
    return json.Unmarshal(output, &results)
}
```

### cfn-nag

**Repository**: `github.com/stelligent/cfn_nag`
**Language**: Ruby
**License**: MIT
**Purpose**: CloudFormation security analysis

**Key Features**:
- Security-focused CloudFormation analysis
- Detects insecure infrastructure patterns
- 200+ built-in security rules
- Custom rule support

**Go Integration**: Execute as subprocess

**Installation**:
```bash
gem install cfn-nag
```

### cfn-guard (Recommended for Security Analysis)

**Repository**: `github.com/aws-cloudformation/cloudformation-guard`
**Language**: Rust
**License**: Apache-2.0
**Purpose**: Policy-as-code validation for CloudFormation templates

**Key Features**:
- High-performance Rust implementation
- Domain-specific language (DSL) for writing rules
- Support for CloudFormation, Kubernetes, Terraform JSON
- Native binary with excellent performance
- CI/CD pipeline integration

**Installation**:
```bash
cargo install cfn-guard
```

**Go Integration Example**:
```go
import (
    "os/exec"
    "encoding/json"
)

type GuardResult struct {
    Status   string `json:"status"`
    Filename string `json:"filename"`
    // ... other fields
}

func validateWithGuard(templatePath, rulesPath string) (*GuardResult, error) {
    cmd := exec.Command("cfn-guard", "validate", 
        "--data", templatePath,
        "--rules", rulesPath,
        "--output-format", "json")
    
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    
    var result GuardResult
    err = json.Unmarshal(output, &result)
    return &result, err
}
```

**DSL Example**:
```guard
# Ensure S3 buckets have versioning enabled
AWS::S3::Bucket {
    Properties {
        VersioningConfiguration exists
        VersioningConfiguration {
            Status == "Enabled"
        }
    }
}
```

## 4. Security Analysis Tools Integration

### Checkov

**Repository**: `github.com/bridgecrewio/checkov`
**Language**: Python
**License**: Apache-2.0
**Purpose**: Infrastructure as Code security scanning

**Key Features**:
- 1000+ built-in policies
- Support for CloudFormation, Terraform, Kubernetes, etc.
- CIS benchmarks, PCI DSS, GDPR compliance
- CI/CD integration
- Custom policy support

**CloudFormation Support**:
- Validates CloudFormation templates against security best practices
- Detects misconfigurations like open security groups, unencrypted storage
- Framework-specific scanning with `--framework cloudformation`

**Go Integration**:
```go
func runCheckov(templatePath string) error {
    cmd := exec.Command("checkov", 
        "--framework", "cloudformation",
        "--file", templatePath,
        "--output", "json")
    
    output, err := cmd.Output()
    // Process JSON output
    return err
}
```

### Integration Comparison

| Tool | Language | Performance | Rule Coverage | Go Integration | Maintenance |
|------|----------|-------------|---------------|----------------|-------------|
| cfn-lint | Python | Medium | Syntax + Best Practices | Subprocess | Active (AWS) |
| cfn-nag | Ruby | Low | Security Focus | Subprocess | Community |
| cfn-guard | Rust | High | Custom DSL | Subprocess | Active (AWS) |
| checkov | Python | Medium | Comprehensive | Subprocess | Active (Bridgecrew) |

## 5. Infrastructure Analysis Tool Examples

### Terraform Ecosystem

**terraform-compliance**: Policy compliance testing framework for Terraform
- Language: Python
- Integration: External process
- Use case: BDD-style compliance testing

**tflint**: Terraform linter focused on errors and best practices
- Language: Go
- Integration: Direct library or subprocess
- Features: Pluggable rule sets, cloud provider rules

**terrascan**: Infrastructure as Code security scanner
- Language: Go
- Integration: Direct library integration possible
- Features: 500+ policies, multiple IaC formats

### Pulumi Ecosystem

**Pulumi Policy as Code**: Native policy framework
- Language: Multiple (Go, Python, TypeScript)
- Integration: Direct API integration
- Features: Real-time policy enforcement

### Multi-Tool Platforms

**Spacelift**: Infrastructure automation platform
- Supports: CloudFormation, Terraform, Pulumi
- Features: Policy enforcement, workflow automation
- Integration: API-based

**env0**: Infrastructure automation and governance
- Supports: Terraform, CloudFormation, Terragrunt
- Features: Cost management, policy enforcement
- Integration: API-based

## 6. License Compatibility Analysis

### License Matrix

| Tool/Library | License | Commercial Use | Modification | Distribution | Patent Grant |
|--------------|---------|---------------|--------------|--------------|--------------|
| GoFormation | Apache-2.0 | ✅ | ✅ | ✅ | ✅ |
| Rain Parse | Apache-2.0 | ✅ | ✅ | ✅ | ✅ |
| go-cloudformation | BSD-2-Clause | ✅ | ✅ | ✅ | ❌ |
| cfn-lint | MIT-0 | ✅ | ✅ | ✅ | ❌ |
| cfn-nag | MIT | ✅ | ✅ | ✅ | ❌ |
| cfn-guard | Apache-2.0 | ✅ | ✅ | ✅ | ✅ |
| checkov | Apache-2.0 | ✅ | ✅ | ✅ | ✅ |

### License Compatibility Rules

1. **Apache 2.0 with MIT/BSD**: ✅ Compatible - can combine in same project
2. **All permissive licenses**: ✅ Compatible with proprietary and open source
3. **Patent protection**: Apache 2.0 provides patent grant, MIT/BSD do not
4. **GPL compatibility**: All licenses compatible with GPL v3, Apache 2.0 has issues with GPL v2

### Threagile Integration Considerations

Since Threagile uses Apache-2.0 license:
- **Perfect compatibility** with GoFormation, Rain, cfn-guard, checkov
- **Compatible** with MIT-licensed tools (cfn-lint, cfn-nag)
- **Compatible** with BSD-licensed tools (go-cloudformation)
- **No license conflicts** for any combination of these tools

## Implementation Recommendations

### Primary Recommendation: GoFormation + cfn-guard

**Architecture**:
```go
package cloudformation

import (
    "github.com/awslabs/goformation/v7"
    "github.com/awslabs/goformation/v7/cloudformation"
)

type CloudFormationAnalyzer struct {
    parser    *goformation.Template
    validator *GuardValidator
}

func (c *CloudFormationAnalyzer) ParseTemplate(templatePath string) error {
    template, err := goformation.Open(templatePath)
    if err != nil {
        return err
    }
    c.parser = template
    return nil
}

func (c *CloudFormationAnalyzer) ExtractTechnicalAssets() []*types.TechnicalAsset {
    var assets []*types.TechnicalAsset
    
    // Extract EC2 instances
    for name, resource := range c.parser.Resources {
        switch r := resource.(type) {
        case *ec2.Instance:
            asset := &types.TechnicalAsset{
                Id:    name,
                Title: name,
                Type:  types.VM,
                // ... map CloudFormation properties to Threagile types
            }
            assets = append(assets, asset)
        case *s3.Bucket:
            asset := &types.TechnicalAsset{
                Id:   name,
                Type: types.Datastore,
                // ... map S3 properties
            }
            assets = append(assets, asset)
        }
    }
    
    return assets
}

func (c *CloudFormationAnalyzer) ValidateSecurity(rulesPath string) error {
    return c.validator.ValidateTemplate(c.parser, rulesPath)
}
```

### Alternative Approach: Rain + External Validation

For lighter weight integration:
```go
package cloudformation

import (
    "github.com/aws-cloudformation/rain/cfn/parse"
    "os/exec"
)

type LightweightAnalyzer struct {
    template cfn.Template
}

func (l *LightweightAnalyzer) ParseTemplate(templatePath string) error {
    template, err := parse.File(templatePath)
    l.template = template
    return err
}

func (l *LightweightAnalyzer) ValidateWithExternalTools(templatePath string) error {
    // Run cfn-guard
    if err := l.runGuard(templatePath); err != nil {
        return err
    }
    
    // Run checkov for additional security checks
    return l.runCheckov(templatePath)
}
```

### Integration Strategy

1. **Phase 1**: Basic CloudFormation parsing with GoFormation
   - Parse CloudFormation templates
   - Extract basic resource information
   - Map to Threagile data structures

2. **Phase 2**: Security validation integration
   - Integrate cfn-guard for policy validation
   - Add checkov for comprehensive security analysis
   - Generate security findings

3. **Phase 3**: Advanced features
   - CloudFormation intrinsic function evaluation
   - Stack relationship analysis
   - Custom security rules for Threagile-specific threats

### Resource Mapping Strategy

Map CloudFormation resources to Threagile concepts:

```go
// CloudFormation -> Threagile mapping
var resourceTypeMapping = map[string]types.TechnicalAssetType{
    "AWS::EC2::Instance":           types.VM,
    "AWS::ECS::Service":           types.Container,
    "AWS::Lambda::Function":        types.Function,
    "AWS::RDS::DBInstance":        types.Datastore,
    "AWS::S3::Bucket":             types.Datastore,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": types.LoadBalancer,
    "AWS::ApiGateway::RestApi":     types.Gateway,
    "AWS::EKS::Cluster":           types.Container,
}
```

## Performance Considerations

### Library Performance Comparison

| Tool | Language | Memory Usage | Parse Speed | Binary Size |
|------|----------|--------------|-------------|-------------|
| GoFormation | Go | Medium | Fast | Medium |
| Rain Parse | Go | Low | Fast | Small |
| cfn-guard | Rust | Low | Very Fast | Small |
| cfn-lint | Python | High | Medium | Large (Runtime) |
| checkov | Python | High | Slow | Large (Runtime) |

### Recommendations for Threagile

1. **Use GoFormation** for primary parsing (best Go integration)
2. **Use cfn-guard** for security validation (best performance)
3. **Consider checkov** for comprehensive analysis (slower but thorough)
4. **Cache parsed templates** to avoid re-parsing
5. **Parallel processing** for multiple template analysis

## Conclusion

For Threagile's CloudFormation integration, the recommended approach combines:

1. **GoFormation** as the primary parsing library for its comprehensive Go integration and AWS Labs maintenance
2. **cfn-guard** for high-performance security validation with custom rules
3. **Checkov** as an optional additional security scanner for comprehensive coverage

This combination provides:
- ✅ Excellent license compatibility (all Apache-2.0/MIT)
- ✅ Strong Go ecosystem integration
- ✅ Comprehensive security analysis capabilities
- ✅ Active maintenance and community support
- ✅ High performance suitable for CI/CD integration
- ✅ Extensibility for custom Threagile-specific rules

The implementation should follow a phased approach, starting with basic parsing and gradually adding security validation capabilities to provide comprehensive CloudFormation threat modeling integration.