package ai

import (
	"github.com/threagile/threagile/pkg/types"
)

// AssetType represents the type of technical asset
type AssetType string

const (
	AssetTypeCompute     AssetType = "compute"
	AssetTypeStorage     AssetType = "storage"
	AssetTypeNetwork     AssetType = "network"
	AssetTypeLoadBalancer AssetType = "loadbalancer"
	AssetTypeDatabase    AssetType = "database"
	AssetTypeContainer   AssetType = "container"
	AssetTypeServerless  AssetType = "serverless"
	AssetTypeService     AssetType = "service"
)

// BoundaryType represents the type of trust boundary
type BoundaryType string

const (
	BoundaryTypeNetwork     BoundaryType = "network-segment"
	BoundaryTypeCloudAccount BoundaryType = "cloud-account"
	BoundaryTypeK8sNamespace BoundaryType = "k8s-namespace"
	BoundaryTypeVPC         BoundaryType = "vpc"
	BoundaryTypeSubnet      BoundaryType = "subnet"
	BoundaryTypeEnvironment BoundaryType = "environment"
)

// GeneratorMode controls the level of detail in generation
type GeneratorMode string

const (
	GeneratorModeSimple   GeneratorMode = "simple"
	GeneratorModeDetailed GeneratorMode = "detailed"
)

// TechnicalAsset represents a discovered infrastructure component
type TechnicalAsset struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        AssetType              `json:"type"`
	Technology  types.Technology       `json:"technology,omitempty"`
	Machine     types.TechnicalAssetMachine `json:"machine,omitempty"`
	Internet    bool                   `json:"internet,omitempty"`
	Encryption  types.EncryptionStyle  `json:"encryption,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	IACSource   string                 `json:"iac_source"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

// TrustBoundary represents a security boundary
type TrustBoundary struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        BoundaryType           `json:"type"`
	Assets      []string               `json:"assets"`
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

// CommunicationLink represents a connection between assets
type CommunicationLink struct {
	ID          string                 `json:"id"`
	SourceID    string                 `json:"source_id"`
	TargetID    string                 `json:"target_id"`
	Title       string                 `json:"title"`
	Protocol    types.Protocol         `json:"protocol,omitempty"`
	Encryption  types.EncryptionStyle  `json:"encryption,omitempty"`
	Authentication types.Authentication `json:"authentication,omitempty"`
	DataAssets  []string               `json:"data_assets,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

// DataAsset represents data processed or stored
type DataAsset struct {
	ID             string                 `json:"id"`
	Title          string                 `json:"title"`
	Classification types.Confidentiality  `json:"classification"`
	Quantity       types.Quantity         `json:"quantity,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	Properties     map[string]interface{} `json:"properties,omitempty"`
}

// GeneratorOptions controls model generation
type GeneratorOptions struct {
	Mode            GeneratorMode  `json:"mode"`
	MergeExisting   bool           `json:"merge_existing"`
	ExistingModel   *types.Model   `json:"-"`
	ContextFiles    []string       `json:"context_files,omitempty"`
	DefaultBoundary string         `json:"default_boundary,omitempty"`
}

// ValidationResult contains validation findings
type ValidationResult struct {
	Valid       bool                `json:"valid"`
	Errors      []ValidationError   `json:"errors,omitempty"`
	Warnings    []ValidationWarning `json:"warnings,omitempty"`
	Suggestions []string            `json:"suggestions,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Asset   string `json:"asset,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Asset   string `json:"asset,omitempty"`
}

// AIContext contains project context from AI tool files
type AIContext struct {
	ProjectName        string            `json:"project_name,omitempty"`
	SecurityPolicies   []string          `json:"security_policies,omitempty"`
	ComplianceFrameworks []string        `json:"compliance_frameworks,omitempty"`
	Architecture       map[string]string `json:"architecture,omitempty"`
	CustomTags         []string          `json:"custom_tags,omitempty"`
}

// OrchestratorOptions controls the orchestration process
type OrchestratorOptions struct {
	Directories    []string         `json:"directories"`
	Mode           GeneratorMode    `json:"mode"`
	ContextFiles   []string         `json:"context_files,omitempty"`
	OutputPath     string           `json:"output_path"`
	MergeWithPath  string           `json:"merge_with_path,omitempty"`
	JSONOutput     bool             `json:"json_output"`
}