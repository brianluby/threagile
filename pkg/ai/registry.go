package ai

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// registry manages available parsers
type registry struct {
	mu      sync.RWMutex
	parsers map[string]Parser
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry() ParserRegistry {
	return &registry{
		parsers: make(map[string]Parser),
	}
}

// Register adds a parser to the registry
func (r *registry) Register(parser Parser) error {
	if parser == nil {
		return fmt.Errorf("parser cannot be nil")
	}

	name := parser.Name()
	if name == "" {
		return fmt.Errorf("parser name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.parsers[name]; exists {
		return fmt.Errorf("parser %s already registered", name)
	}

	r.parsers[name] = parser
	return nil
}

// GetParser returns a parser by name
func (r *registry) GetParser(name string) (Parser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	parser, exists := r.parsers[name]
	if !exists {
		return nil, fmt.Errorf("parser %s not found", name)
	}

	return parser, nil
}

// GetParserForFile returns appropriate parser for a file based on extension
func (r *registry) GetParserForFile(filePath string) (Parser, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return nil, fmt.Errorf("file has no extension: %s", filePath)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check each parser's supported extensions
	for _, parser := range r.parsers {
		for _, supportedExt := range parser.SupportedExtensions() {
			if ext == supportedExt {
				// Additional check for Kubernetes files
				if parser.Name() == "kubernetes" {
					// Only return K8s parser if file actually contains K8s resources
					// This is handled by the parser's isKubernetesFile method
					return parser, nil
				}
				return parser, nil
			}
		}
	}

	return nil, fmt.Errorf("no parser found for file extension: %s", ext)
}

// ListParsers returns all registered parser names
func (r *registry) ListParsers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		names = append(names, name)
	}

	return names
}

// DefaultRegistry is a global registry instance for convenience
var DefaultRegistry = NewParserRegistry()

// Note: The actual parser registration happens in the respective packages
// using RegisterParser functions to avoid circular imports.
// See terraform.RegisterParser() and kubernetes.RegisterParser()
//
// Example usage:
//   registry := ai.NewParserRegistry()
//   terraform.RegisterParser(registry)
//   kubernetes.RegisterParser(registry)