package ai

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrchestrator_GenerateModel(t *testing.T) {
	// Create test registry with stub parsers
	registry := NewParserRegistry()
	registry.Register(&stubParser{
		name:       "test",
		extensions: []string{".test"},
		parseFunc: func(files []string) (*ParseResult, error) {
			return &ParseResult{
				TechnicalAssets: []TechnicalAsset{
					{
						ID:    "test-asset-1",
						Title: "Test Asset 1",
						Type:  AssetTypeCompute,
						Properties: map[string]interface{}{
							"vpc": "test-vpc",
						},
					},
				},
				TrustBoundaries: []TrustBoundary{
					{
						ID:    "test-boundary",
						Title: "Test Boundary",
						Type:  BoundaryTypeVPC,
					},
				},
			}, nil
		},
	})

	orchestrator := NewOrchestrator(registry)

	// Create test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.test")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Test model generation
	options := OrchestratorOptions{
		Directories: []string{tmpDir},
		Mode:        GeneratorModeSimple,
	}

	model, err := orchestrator.GenerateModel(options)
	require.NoError(t, err)
	require.NotNil(t, model)

	// Verify model contents
	assert.Equal(t, "Generated Threat Model", model.Title)
	assert.Len(t, model.TechnicalAssets, 1)
	assert.Len(t, model.TrustBoundaries, 1)
	
	// Check technical asset
	asset, exists := model.TechnicalAssets["test-asset-1"]
	assert.True(t, exists)
	assert.Equal(t, "Test Asset 1", asset.Title)
	
	// Check trust boundary
	boundary, exists := model.TrustBoundaries["test-boundary"]
	assert.True(t, exists)
	assert.Equal(t, "Test Boundary", boundary.Title)
}

func TestOrchestrator_ParseDirectories(t *testing.T) {
	// Create test registry
	registry := NewParserRegistry()
	
	parseCount := 0
	registry.Register(&stubParser{
		name:       "counter",
		extensions: []string{".count"},
		parseFunc: func(files []string) (*ParseResult, error) {
			parseCount++
			return &ParseResult{
				TechnicalAssets: []TechnicalAsset{
					{
						ID:    "asset-" + string(rune(parseCount)),
						Title: "Asset " + string(rune(parseCount)),
						Type:  AssetTypeCompute,
					},
				},
			}, nil
		},
	})

	orchestrator := &orchestrator{registry: registry}

	// Create test directory with multiple files
	tmpDir := t.TempDir()
	for i := 0; i < 3; i++ {
		testFile := filepath.Join(tmpDir, "file"+string(rune('0'+i))+".count")
		err := os.WriteFile(testFile, []byte("content"), 0644)
		require.NoError(t, err)
	}

	// Parse directory
	results, err := orchestrator.ParseDirectories([]string{tmpDir})
	require.NoError(t, err)
	assert.Len(t, results, 1) // One result from the parser
	assert.Equal(t, 1, parseCount) // Parser called once with all files
}

func TestOrchestrator_ContextFiles(t *testing.T) {
	// Create test context file
	tmpDir := t.TempDir()
	contextFile := filepath.Join(tmpDir, "CLAUDE.md")
	contextContent := `# Project Overview
This is the Test Project.

## Security Requirements
- Encryption required
- GDPR compliance

## Tags
security, compliance, test`

	err := os.WriteFile(contextFile, []byte(contextContent), 0644)
	require.NoError(t, err)

	// Create a test infrastructure file
	testFile := filepath.Join(tmpDir, "test.tf")
	err = os.WriteFile(testFile, []byte("resource \"aws_instance\" \"test\" {}"), 0644)
	require.NoError(t, err)

	// Create orchestrator with stub parser
	registry := NewParserRegistry()
	
	// Register a stub parser that returns minimal results
	stubParser := &stubParser{
		name:       "test",
		extensions: []string{".tf"},
		parseFunc: func(files []string) (*ParseResult, error) {
			return &ParseResult{
				TechnicalAssets: []TechnicalAsset{
					{ID: "test_asset", Title: "Test Asset", Type: AssetTypeCompute},
				},
			}, nil
		},
	}
	require.NoError(t, registry.Register(stubParser))
	
	orchestrator := NewOrchestrator(registry)

	// Generate model with context
	options := OrchestratorOptions{
		Directories:  []string{tmpDir},
		Mode:         GeneratorModeSimple,
		ContextFiles: []string{contextFile},
	}

	model, err := orchestrator.GenerateModel(options)
	require.NoError(t, err)
	require.NotNil(t, model)

	// Verify context was applied
	assert.Equal(t, "Test Project Threat Model", model.Title)
	assert.Contains(t, model.SecurityRequirements, "Encryption required")
	assert.Contains(t, model.SecurityRequirements, "GDPR compliance")
	assert.Contains(t, model.TagsAvailable, "security")
	assert.Contains(t, model.TagsAvailable, "compliance")
	assert.Contains(t, model.TagsAvailable, "test")
}

// Test stub parser with configurable behavior
type stubParser struct {
	name       string
	extensions []string
	parseFunc  func([]string) (*ParseResult, error)
}

func (s *stubParser) Name() string                  { return s.name }
func (s *stubParser) SupportedExtensions() []string { return s.extensions }
func (s *stubParser) Parse(files []string) (*ParseResult, error) {
	if s.parseFunc != nil {
		return s.parseFunc(files)
	}
	return &ParseResult{}, nil
}