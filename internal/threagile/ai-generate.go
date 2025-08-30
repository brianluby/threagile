/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/ai"
	"github.com/threagile/threagile/pkg/iac/kubernetes"
	"github.com/threagile/threagile/pkg/iac/terraform"
	"gopkg.in/yaml.v3"
)

const (
	// Command names
	AIGenerateCommand = "ai-generate"

	// Flag names
	aiModeFlagName         = "mode"
	aiModeFlagShorthand    = "m"
	aiIacDirsFlagName      = "iac-dirs"
	aiIacDirsFlagShorthand = "d"
	aiMergeWithFlagName    = "merge-with"
	aiContextFilesFlagName = "context-files"
	aiContextFlagShorthand = "c"
	aiJsonOutputFlagName   = "json"
	aiJsonFlagShorthand    = "j"
)

func (what *Threagile) initAIGenerate() *Threagile {
	aiCmd := &cobra.Command{
		Use:   AIGenerateCommand,
		Short: "Generate threat model from Infrastructure as Code",
		Long: "\n" + Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp) + "\n\n" +
			"Generate a Threagile threat model by analyzing Infrastructure as Code (IaC) files.\n" +
			"Supports Terraform, Kubernetes, and other IaC formats.\n\n" +
			"Examples:\n" +
			"  threagile ai-generate --iac-dirs terraform/,k8s/\n" +
			"  threagile ai-generate --mode detailed --merge-with existing-model.yaml\n" +
			"  threagile ai-generate --context-files CLAUDE.md --json",
		RunE: what.runAIGenerate,
	}

	// Add flags specific to ai-generate
	aiCmd.Flags().StringP(aiModeFlagName, aiModeFlagShorthand, "simple", "Generation mode: simple only (detailed mode coming soon)")
	aiCmd.Flags().StringSliceP(aiIacDirsFlagName, aiIacDirsFlagShorthand, []string{"."}, "Comma-separated list of directories containing IaC files")
	// TODO: Re-enable when merge functionality is implemented
	// aiCmd.Flags().String(aiMergeWithFlagName, "", "Path to existing model to merge with")
	aiCmd.Flags().StringSliceP(aiContextFilesFlagName, aiContextFlagShorthand, []string{}, "AI context files (e.g., CLAUDE.md)")
	aiCmd.Flags().BoolP(aiJsonOutputFlagName, aiJsonFlagShorthand, false, "Output results as JSON")

	what.rootCmd.AddCommand(aiCmd)
	return what
}

func (what *Threagile) runAIGenerate(cmd *cobra.Command, args []string) error {
	what.processArgs(cmd, args)

	// Parse flags
	mode, err := cmd.Flags().GetString(aiModeFlagName)
	if err != nil {
		return fmt.Errorf("unable to read mode flag: %w", err)
	}

	iacDirs, err := cmd.Flags().GetStringSlice(aiIacDirsFlagName)
	if err != nil {
		return fmt.Errorf("unable to read iac-dirs flag: %w", err)
	}

	// TODO: Re-enable when merge functionality is implemented
	// mergeWith, err := cmd.Flags().GetString(aiMergeWithFlagName)
	// if err != nil {
	//     return fmt.Errorf("unable to read merge-with flag: %w", err)
	// }
	mergeWith := "" // Temporary until merge is implemented

	contextFiles, err := cmd.Flags().GetStringSlice(aiContextFilesFlagName)
	if err != nil {
		return fmt.Errorf("unable to read context-files flag: %w", err)
	}

	jsonOutput, err := cmd.Flags().GetBool(aiJsonOutputFlagName)
	if err != nil {
		return fmt.Errorf("unable to read json flag: %w", err)
	}

	outputPath := what.config.GetInputFile()
	if outputPath == "" {
		outputPath = "threagile-generated.yaml"
	}

	// Print header unless in JSON mode
	if !jsonOutput {
		cmd.Println(Logo + "\n\n" + fmt.Sprintf(VersionText, what.buildTimestamp))
		cmd.Println("\nGenerating threat model from Infrastructure as Code...")
		cmd.Printf("Mode: %s\n", mode)
		cmd.Printf("IaC Directories: %s\n", strings.Join(iacDirs, ", "))
		if mergeWith != "" {
			cmd.Printf("Merging with: %s\n", mergeWith)
		}
		if len(contextFiles) > 0 {
			cmd.Printf("Context files: %s\n", strings.Join(contextFiles, ", "))
		}
		cmd.Println()
	}

	// Create parser registry and register parsers
	registry := ai.NewParserRegistry()
	
	// Register Terraform parser
	if err := terraform.RegisterParser(registry); err != nil {
		return fmt.Errorf("failed to register terraform parser: %w", err)
	}
	
	// Register Kubernetes parser
	if err := kubernetes.RegisterParser(registry); err != nil {
		return fmt.Errorf("failed to register kubernetes parser: %w", err)
	}

	// Create orchestrator
	orchestrator := ai.NewOrchestrator(registry)

	// Prepare options
	options := ai.OrchestratorOptions{
		Directories:   iacDirs,
		Mode:          ai.GeneratorMode(mode),
		ContextFiles:  contextFiles,
		OutputPath:    outputPath,
		MergeWithPath: mergeWith,
		JSONOutput:    jsonOutput,
	}

	// Generate model
	model, err := orchestrator.GenerateModel(options)
	if err != nil {
		return fmt.Errorf("failed to generate model: %w", err)
	}

	// Output results
	if jsonOutput {
		// Output JSON summary
		summary := map[string]interface{}{
			"success":          true,
			"model_path":       outputPath,
			"technical_assets": len(model.TechnicalAssets),
			"trust_boundaries": len(model.TrustBoundaries),
			"data_assets":      len(model.DataAssets),
			"risks_found":      0, // Will be populated after risk analysis
		}
		
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(summary); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	} else {
		// Save model to YAML file
		yamlData, err := yaml.Marshal(model)
		if err != nil {
			return fmt.Errorf("failed to marshal model to YAML: %w", err)
		}

		// Ensure output directory exists
		outputDir := filepath.Dir(outputPath)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Write file
		if err := os.WriteFile(outputPath, yamlData, 0644); err != nil {
			return fmt.Errorf("failed to write model file: %w", err)
		}

		// Print summary
		cmd.Println("✅ Threat model generated successfully!")
		cmd.Printf("\nSummary:\n")
		cmd.Printf("  Technical Assets: %d\n", len(model.TechnicalAssets))
		cmd.Printf("  Trust Boundaries: %d\n", len(model.TrustBoundaries))
		cmd.Printf("  Data Assets:      %d\n", len(model.DataAssets))
		cmd.Printf("  Communications:   %d\n", len(model.CommunicationLinks))
		cmd.Printf("\nModel saved to: %s\n", outputPath)
		
		cmd.Println("\nNext steps:")
		cmd.Printf("  1. Review the generated model: %s\n", outputPath)
		cmd.Println("  2. Run threat analysis: threagile analyze-model")
		cmd.Println("  3. Generate reports: threagile analyze-model --generate-report-pdf")
	}

	return nil
}