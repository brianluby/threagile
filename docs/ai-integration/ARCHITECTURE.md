# AI Integration Architecture for Threagile

## Overview

This document describes the architecture for integrating AI capabilities into Threagile, focusing on Phase 1 MVP: Simple Mode with automated trust boundary detection from Infrastructure as Code (IaC) files.

## Design Principles

1. **Modular**: Each IaC parser is a separate module implementing common interfaces
2. **Extensible**: Easy to add new parsers and AI tool support
3. **Non-invasive**: AI features are optional and don't affect existing functionality
4. **CI/CD Friendly**: Designed for automation with proper exit codes and JSON output
5. **Progressive Enhancement**: Start simple, add complexity incrementally

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI/API Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ threagile    │  │ REST API     │  │ GitHub Actions  │  │
│  │ ai-generate  │  │ /ai/validate │  │ Integration     │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└────────────────────────────┬───────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────┐
│                    AI Core (pkg/ai)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Orchestrator │  │ Model        │  │ Trust Boundary  │  │
│  │              │  │ Generator    │  │ Detector        │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
│         │                                                   │
│  ┌──────▼────────────────────────────────────────────┐    │
│  │              Parser Registry                       │    │
│  └──────┬────────────────┬────────────────┬─────────┘    │
└─────────┼────────────────┼────────────────┼───────────────┘
          │                │                │
┌─────────▼──────┐ ┌───────▼──────┐ ┌──────▼──────┐
│ Terraform      │ │ Kubernetes   │ │ CloudForm.  │
│ Parser         │ │ Parser       │ │ Parser      │
│ (pkg/iac/     │ │ (pkg/iac/    │ │ (pkg/iac/   │
│  terraform)    │ │  kubernetes) │ │  aws)       │
└────────────────┘ └──────────────┘ └─────────────┘
```

## Core Components

### 1. AI Core Package (`pkg/ai`)

#### Interfaces (`interfaces.go`)
```go
// Parser extracts infrastructure information from IaC files
type Parser interface {
    // Parse analyzes files and returns discovered resources
    Parse(files []string) (*ParseResult, error)
    
    // SupportedExtensions returns file extensions this parser handles
    SupportedExtensions() []string
    
    // Name returns the parser name (e.g., "terraform", "kubernetes")
    Name() string
}

// ParseResult contains discovered infrastructure elements
type ParseResult struct {
    TechnicalAssets []TechnicalAsset
    TrustBoundaries []TrustBoundary
    Communications  []CommunicationLink
    DataAssets      []DataAsset
    Metadata        map[string]interface{}
}

// Generator creates Threagile models from parsed data
type Generator interface {
    // Generate creates a Threagile model from parse results
    Generate(results []*ParseResult, options GeneratorOptions) (*Model, error)
}

// TrustBoundaryDetector identifies security boundaries
type TrustBoundaryDetector interface {
    // DetectBoundaries analyzes assets and suggests trust boundaries
    DetectBoundaries(assets []TechnicalAsset) []TrustBoundary
}

// Validator checks model consistency
type Validator interface {
    // ValidateIncremental checks if changes are safe
    ValidateIncremental(oldModel, newModel *Model) (*ValidationResult, error)
}
```

#### Types (`types.go`)
```go
// TechnicalAsset represents a discovered infrastructure component
type TechnicalAsset struct {
    ID          string
    Title       string
    Type        AssetType // compute, storage, network, etc.
    Tags        []string
    IACSource   string    // source file
    Properties  map[string]interface{}
}

// TrustBoundary represents a security boundary
type TrustBoundary struct {
    ID          string
    Title       string
    Type        BoundaryType // network-segment, cloud-account, k8s-namespace
    Assets      []string     // asset IDs
    Properties  map[string]interface{}
}

// GeneratorOptions controls model generation
type GeneratorOptions struct {
    Mode            GeneratorMode // simple, detailed
    MergeExisting   bool
    ContextFiles    []string     // CLAUDE.md, etc.
}
```

#### Orchestrator (`orchestrator.go`)
- Manages parser registry
- Coordinates parsing across multiple IaC types
- Handles file discovery and routing
- Merges results from different parsers

#### Simple Mode Generator (`simple_mode.go`)
- Implements minimal viable model generation
- Focuses on trust boundaries and basic assets
- Uses sensible defaults for risk levels
- Generates clean, readable YAML

### 2. IaC Parsers

#### Terraform Parser (`pkg/iac/terraform`)
Extracts from `.tf` and `.tfvars` files:
- VPCs, Subnets → Trust Boundaries
- EC2, ECS, Lambda → Compute Assets
- RDS, S3, DynamoDB → Storage Assets
- Security Groups → Access rules
- IAM Roles → Permission boundaries

#### Kubernetes Parser (`pkg/iac/kubernetes`)
Extracts from YAML manifests:
- Namespaces → Trust Boundaries
- Deployments/Pods → Compute Assets
- Services → Communication endpoints
- Ingress → External access points
- PersistentVolumes → Storage Assets
- NetworkPolicies → Access rules

### 3. CLI Integration

#### New Command: `threagile ai-generate`
```bash
threagile ai-generate \
  --mode simple \
  --iac-dirs ./terraform,./k8s \
  --output threagile-generated.yaml \
  --context-file CLAUDE.md
```

Options:
- `--mode`: simple (MVP) or detailed
- `--iac-dirs`: Directories to scan
- `--merge-with`: Existing model to update
- `--context-file`: AI tool context files
- `--json`: Output JSON for CI/CD

### 4. REST API Extensions

New endpoints:
- `POST /api/v1/ai/parse` - Parse IaC files
- `POST /api/v1/ai/generate` - Generate model
- `POST /api/v1/ai/validate` - Validate changes
- `GET /api/v1/ai/suggestions` - Get boundary suggestions

### 5. CI/CD Integration

#### GitHub Action
```yaml
- uses: threagile/threagile-action@v1
  with:
    mode: simple
    iac-dirs: 'terraform/,k8s/'
    comment-on-pr: true
    fail-on-high-risk: true
```

## Data Flow

1. **Discovery Phase**
   - Scan specified directories
   - Identify IaC files by extension
   - Route to appropriate parsers

2. **Parsing Phase**
   - Each parser extracts resources
   - Convert to common format
   - Collect metadata for traceability

3. **Analysis Phase**
   - Trust boundary detection
   - Asset relationship mapping
   - Risk pattern identification

4. **Generation Phase**
   - Merge parser results
   - Apply context from AI files
   - Generate Threagile YAML

5. **Validation Phase**
   - Check model consistency
   - Identify missing elements
   - Suggest improvements

## File Structure

```
pkg/
├── ai/
│   ├── interfaces.go      # Core interfaces
│   ├── types.go          # Shared types
│   ├── orchestrator.go   # Main coordinator
│   ├── registry.go       # Parser registry
│   ├── generator.go      # Model generation
│   ├── simple_mode.go    # Simple mode impl
│   ├── trust_boundary.go # Boundary detection
│   ├── context.go        # AI file parsing
│   └── validator.go      # Model validation
├── iac/
│   ├── terraform/
│   │   ├── parser.go     # Terraform parser
│   │   ├── resources.go  # Resource mapping
│   │   └── parser_test.go
│   ├── kubernetes/
│   │   ├── parser.go     # K8s parser
│   │   ├── manifest.go   # Manifest parsing
│   │   └── parser_test.go
│   └── cloudformation/
│       ├── parser.go     # CF parser
│       └── parser_test.go
```

## Security Considerations

1. **File Access**: Only read files, never execute
2. **Path Traversal**: Validate all file paths
3. **Size Limits**: Cap file sizes to prevent DoS
4. **Parsing Safety**: Use safe YAML/JSON parsers
5. **No Credentials**: Never extract secrets/passwords

## Future Enhancements (Phase 2+)

1. **Detailed Mode**: Full asset properties, custom rules
2. **Code Analysis**: Parse application code for APIs
3. **Smart Merging**: Intelligent model updates
4. **AI Suggestions**: LLM-powered recommendations
5. **Multi-Repo**: Scan across repository boundaries

## Success Metrics

- Parse time: < 10s for typical project
- Boundary accuracy: > 85% correct
- Asset coverage: > 90% discovered
- Memory usage: < 500MB for large projects
- CI/CD friendly: Proper exit codes, JSON output