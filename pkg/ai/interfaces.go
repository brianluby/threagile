package ai

import (
	"github.com/threagile/threagile/pkg/types"
)

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
	TechnicalAssets []TechnicalAsset    `json:"technical_assets,omitempty"`
	TrustBoundaries []TrustBoundary     `json:"trust_boundaries,omitempty"`
	Communications  []CommunicationLink `json:"communications,omitempty"`
	DataAssets      []DataAsset         `json:"data_assets,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Generator creates Threagile models from parsed data
type Generator interface {
	// Generate creates a Threagile model from parse results
	Generate(results []*ParseResult, options GeneratorOptions) (*types.Model, error)
}

// TrustBoundaryDetector identifies security boundaries
type TrustBoundaryDetector interface {
	// DetectBoundaries analyzes assets and suggests trust boundaries
	DetectBoundaries(assets []TechnicalAsset) []TrustBoundary
}

// Validator checks model consistency
type Validator interface {
	// ValidateIncremental checks if changes are safe
	ValidateIncremental(oldModel, newModel *types.Model) (*ValidationResult, error)
}

// AIContextReader reads AI tool configuration files
type AIContextReader interface {
	// ReadContext extracts project information from AI tool files
	ReadContext(filePath string) (*AIContext, error)
	
	// SupportedFiles returns the file names this reader handles
	SupportedFiles() []string
}

// ParserRegistry manages available parsers
type ParserRegistry interface {
	// Register adds a parser to the registry
	Register(parser Parser) error
	
	// GetParser returns a parser by name
	GetParser(name string) (Parser, error)
	
	// GetParserForFile returns appropriate parser for a file
	GetParserForFile(filePath string) (Parser, error)
	
	// ListParsers returns all registered parser names
	ListParsers() []string
}

// Orchestrator coordinates the AI model generation process
type Orchestrator interface {
	// GenerateModel orchestrates the full model generation process
	GenerateModel(options OrchestratorOptions) (*types.Model, error)
	
	// ParseDirectories scans directories for IaC files
	ParseDirectories(dirs []string) ([]*ParseResult, error)
}