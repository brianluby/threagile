package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/threagile/threagile/pkg/types"
	"github.com/threagile/threagile/pkg/utils"
)

// orchestrator coordinates the AI model generation process
type orchestrator struct {
	registry         ParserRegistry
	generator        Generator
	boundaryDetector TrustBoundaryDetector
	contextReaders   []AIContextReader
}

// NewOrchestrator creates a new orchestrator instance
func NewOrchestrator(registry ParserRegistry) Orchestrator {
	return &orchestrator{
		registry:         registry,
		generator:        nil, // Set based on mode in GenerateModel
		boundaryDetector: NewSimpleBoundaryDetector(),
		contextReaders:   []AIContextReader{
			NewClaudeMDReader(),
		},
	}
}

// GenerateModel orchestrates the full model generation process
func (o *orchestrator) GenerateModel(options OrchestratorOptions) (*types.Model, error) {
	// 0. Set generator based on mode
	switch options.Mode {
	case GeneratorModeSimple:
		o.generator = NewSimpleGenerator()
	case GeneratorModeDetailed:
		return nil, fmt.Errorf("detailed mode is not yet implemented, please use 'simple' mode")
	default:
		return nil, fmt.Errorf("invalid mode: %s (must be 'simple' or 'detailed')", options.Mode)
	}

	// 1. Read context files if provided
	var contexts []*AIContext
	for _, ctxFile := range options.ContextFiles {
		ctx, err := o.readContextFile(ctxFile)
		if err != nil {
			// Log warning but continue
			fmt.Fprintf(os.Stderr, "Warning: failed to read context file %s: %v\n", ctxFile, err)
			continue
		}
		if ctx != nil {
			contexts = append(contexts, ctx)
		}
	}

	// 2. Parse all directories
	parseResults, err := o.ParseDirectories(options.Directories)
	if err != nil {
		return nil, fmt.Errorf("failed to parse directories: %w", err)
	}

	if len(parseResults) == 0 {
		return nil, fmt.Errorf("no infrastructure files found in directories: %v", options.Directories)
	}

	// 3. Load existing model if merge requested
	var existingModel *types.Model
	if options.MergeWithPath != "" {
		// TODO: Implement model loading and merging
		// This requires integrating with Threagile's existing model loader
		return nil, fmt.Errorf("merge functionality is not yet implemented")
	}

	// 4. Generate model
	genOptions := GeneratorOptions{
		Mode:          options.Mode,
		MergeExisting: existingModel != nil,
		ExistingModel: existingModel,
		ContextFiles:  options.ContextFiles,
	}

	model, err := o.generator.Generate(parseResults, genOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate model: %w", err)
	}

	// 5. Apply context information
	o.applyContexts(model, contexts)

	// 6. Validate model
	if err := o.validateModel(model); err != nil {
		return nil, fmt.Errorf("model validation failed: %w", err)
	}

	return model, nil
}

// ParseDirectories scans directories for IaC files and parses them
func (o *orchestrator) ParseDirectories(dirs []string) ([]*ParseResult, error) {
	var allResults []*ParseResult

	// Group files by parser
	filesByParser := make(map[IaCParser][]string)

	// Scan all directories
	for _, dir := range dirs {
		if err := o.scanDirectory(dir, filesByParser); err != nil {
			return nil, fmt.Errorf("failed to scan directory %s: %w", dir, err)
		}
	}

	// Parse files with each parser
	for parser, files := range filesByParser {
		if len(files) == 0 {
			continue
		}

		fmt.Printf("Parsing %d files...\n", len(files))
		
		// Parse each file individually
		for _, file := range files {
			content, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s: %w", file, err)
			}
			
			result, err := parser.ParseFile(file, content)
			if err != nil {
				return nil, fmt.Errorf("parser failed on file %s: %w", file, err)
			}

			if result != nil {
				allResults = append(allResults, result)
			}
		}
	}

	return allResults, nil
}

// scanDirectory recursively scans a directory and groups files by parser
func (o *orchestrator) scanDirectory(dir string, filesByParser map[IaCParser][]string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and hidden files
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Find appropriate parser
		parser, found := o.registry.GetParserForFile(path)
		if !found {
			// No parser for this file type, skip it
			return nil
		}

		filesByParser[parser] = append(filesByParser[parser], path)
		return nil
	})
}

// readContextFile reads an AI context file
func (o *orchestrator) readContextFile(filePath string) (*AIContext, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, nil // File doesn't exist, skip
	}

	// Try each reader
	for _, reader := range o.contextReaders {
		for _, supportedFile := range reader.SupportedFiles() {
			if strings.HasSuffix(filePath, supportedFile) {
				return reader.ReadContext(filePath)
			}
		}
	}

	// No reader found
	return nil, fmt.Errorf("no context reader for file: %s", filePath)
}

// applyContexts applies context information to the model
func (o *orchestrator) applyContexts(model *types.Model, contexts []*AIContext) {
	for _, ctx := range contexts {
		// Apply project name if not set
		if model.Title == "Generated Threat Model" && ctx.ProjectName != "" {
			model.Title = ctx.ProjectName + " Threat Model"
		}

		// Add custom tags
		for _, tag := range ctx.CustomTags {
			if model.TagsAvailable == nil {
				model.TagsAvailable = []string{}
			}
			if !utils.Contains(model.TagsAvailable, tag) {
				model.TagsAvailable = append(model.TagsAvailable, tag)
			}
		}

		// Add security requirements
		if len(ctx.SecurityPolicies) > 0 {
			if model.SecurityRequirements == nil {
				model.SecurityRequirements = make(map[string]string)
			}
			for _, policy := range ctx.SecurityPolicies {
				model.SecurityRequirements[policy] = "Required by " + ctx.ProjectName
			}
		}

		// TODO: Apply more context information as needed
	}
}

// validateModel performs basic validation on the generated model
func (o *orchestrator) validateModel(model *types.Model) error {
	// Basic validation
	if model.Title == "" {
		return fmt.Errorf("model title is required")
	}

	if len(model.TechnicalAssets) == 0 {
		return fmt.Errorf("no technical assets found")
	}

	// Validate asset references
	for _, asset := range model.TechnicalAssets {
		for _, link := range asset.CommunicationLinks {
			if _, exists := model.TechnicalAssets[link.TargetId]; !exists {
				return fmt.Errorf("communication link references non-existent target: %s", link.TargetId)
			}
		}
	}

	// Validate trust boundary references
	for _, boundary := range model.TrustBoundaries {
		for _, assetID := range boundary.TechnicalAssetsInside {
			if _, exists := model.TechnicalAssets[assetID]; !exists {
				return fmt.Errorf("trust boundary references non-existent asset: %s", assetID)
			}
		}
	}

	return nil
}

