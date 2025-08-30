package ai

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	
	"github.com/threagile/threagile/pkg/utils"
)

// claudeMDReader reads CLAUDE.md and similar AI tool configuration files
type claudeMDReader struct{}

// NewClaudeMDReader creates a new CLAUDE.md reader
func NewClaudeMDReader() AIContextReader {
	return &claudeMDReader{}
}

// SupportedFiles returns the file names this reader handles
func (r *claudeMDReader) SupportedFiles() []string {
	return []string{
		"CLAUDE.md",
		".claude/claude.md",
		".github/copilot-instructions.md",
		".cursorrules",
		".aider.conf",
	}
}

// ReadContext extracts project information from AI tool files
func (r *claudeMDReader) ReadContext(filePath string) (*AIContext, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open context file: %w", err)
	}
	defer file.Close()

	context := &AIContext{
		Architecture:         make(map[string]string),
		SecurityPolicies:     []string{},
		ComplianceFrameworks: []string{},
		CustomTags:           []string{},
	}

	scanner := bufio.NewScanner(file)
	section := ""
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines
		if line == "" {
			continue
		}
		
		// Detect sections
		if strings.HasPrefix(line, "#") {
			section = strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#")))
			continue
		}
		
		// Parse based on current section
		switch {
		case strings.Contains(section, "project") || strings.Contains(section, "overview"):
			if context.ProjectName == "" {
				// Try to extract project name from various patterns
				if strings.Contains(line, "name:") || strings.Contains(line, "Name:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						context.ProjectName = strings.TrimSpace(parts[1])
					}
				} else if strings.Contains(line, "This is") || strings.Contains(line, "This project") {
					// Extract from sentences like "This is the XYZ project"
					if name := extractProjectNameFromSentence(line); name != "" {
						context.ProjectName = name
					}
				}
			}
			
		case strings.Contains(section, "security") || strings.Contains(section, "requirements"):
			// Extract security policies
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "•") {
				policy := strings.TrimSpace(strings.TrimLeft(line, "-*•"))
				if policy != "" && !strings.HasPrefix(policy, "#") {
					context.SecurityPolicies = append(context.SecurityPolicies, policy)
				}
			}
			
		case strings.Contains(section, "compliance") || strings.Contains(section, "standards"):
			// Extract compliance frameworks
			if containsComplianceKeywords(line) {
				frameworks := extractComplianceFrameworks(line)
				context.ComplianceFrameworks = append(context.ComplianceFrameworks, frameworks...)
			}
			
		case strings.Contains(section, "architecture") || strings.Contains(section, "components"):
			// Extract architecture information
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					context.Architecture[key] = value
				}
			}
			
		case strings.Contains(section, "tags") || strings.Contains(section, "labels"):
			// Extract custom tags
			tags := extractTags(line)
			context.CustomTags = append(context.CustomTags, tags...)
		}
		
		// Look for inline tags anywhere in the file
		if strings.Contains(line, "tag:") || strings.Contains(line, "tags:") {
			tags := extractTags(line)
			context.CustomTags = append(context.CustomTags, tags...)
		}
		
		// Look for compliance mentions anywhere
		if containsComplianceKeywords(line) {
			frameworks := extractComplianceFrameworks(line)
			context.ComplianceFrameworks = append(context.ComplianceFrameworks, frameworks...)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading context file: %w", err)
	}
	
	// Deduplicate lists
	context.SecurityPolicies = utils.DeduplicateStrings(context.SecurityPolicies)
	context.ComplianceFrameworks = utils.DeduplicateStrings(context.ComplianceFrameworks)
	context.CustomTags = utils.DeduplicateStrings(context.CustomTags)
	
	return context, nil
}

// Helper functions

func extractProjectNameFromSentence(sentence string) string {
	// Common patterns for project names in sentences
	patterns := []string{
		"This is the ",
		"This project is called ",
		"This is ",
		"project for ",
		"repository for ",
	}
	
	for _, pattern := range patterns {
		if idx := strings.Index(sentence, pattern); idx >= 0 {
			start := idx + len(pattern)
			rest := sentence[start:]
			// Handle period at end properly
			rest = strings.TrimSuffix(rest, ".")
			rest = strings.TrimSpace(rest)
			
			// For "This is the X Project" pattern, capture full project name
			if strings.HasSuffix(strings.ToLower(rest), " project") {
				return rest
			}
			// Otherwise return the extracted name
			return rest
		}
	}
	return ""
}

func isCommonWord(word string) bool {
	common := []string{"for", "with", "using", "and", "or", "the", "a", "an", "to", "in", "on"}
	lower := strings.ToLower(word)
	for _, c := range common {
		if lower == c {
			return true
		}
	}
	return false
}

func containsComplianceKeywords(line string) bool {
	keywords := []string{
		"GDPR", "HIPAA", "PCI", "SOC", "ISO", "NIST",
		"compliance", "compliant", "regulation", "standard",
		"FIPS", "FedRAMP", "CCPA", "DSGVO", "27001", "27002",
	}
	
	lower := strings.ToLower(line)
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func extractComplianceFrameworks(line string) []string {
	frameworks := []string{}
	
	// Known compliance frameworks
	knownFrameworks := map[string]string{
		"gdpr":     "GDPR",
		"hipaa":    "HIPAA",
		"pci":      "PCI-DSS",
		"pci-dss":  "PCI-DSS",
		"soc2":     "SOC2",
		"soc 2":    "SOC2",
		"iso27001": "ISO 27001",
		"iso 27001": "ISO 27001",
		"nist":     "NIST",
		"fips":     "FIPS",
		"fedramp":  "FedRAMP",
		"ccpa":     "CCPA",
		"dsgvo":    "DSGVO",
	}
	
	lower := strings.ToLower(line)
	for pattern, framework := range knownFrameworks {
		if strings.Contains(lower, pattern) {
			frameworks = append(frameworks, framework)
		}
	}
	
	return frameworks
}

func extractTags(line string) []string {
	tags := []string{}
	
	// Remove "tag:" or "tags:" prefix
	line = strings.TrimPrefix(line, "tags:")
	line = strings.TrimPrefix(line, "tag:")
	line = strings.TrimSpace(line)
	
	// Handle comma-separated tags
	if strings.Contains(line, ",") {
		parts := strings.Split(line, ",")
		for _, part := range parts {
			tag := strings.TrimSpace(part)
			if tag != "" && !strings.HasPrefix(tag, "#") {
				tags = append(tags, tag)
			}
		}
	} else if strings.Contains(line, " ") {
		// Handle space-separated tags
		words := strings.Fields(line)
		for _, word := range words {
			// Skip if it looks like regular text
			if !strings.Contains(word, ":") && len(word) < 30 {
				tags = append(tags, word)
			}
		}
	} else if line != "" {
		// Single tag
		tags = append(tags, line)
	}
	
	return tags
}

