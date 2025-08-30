# AI Integration Package

This package contains the core AI integration functionality for Threagile.

## Structure
- `interfaces.go` - Core interfaces for AI integration
- `parser.go` - Base parser functionality
- `context.go` - AI tool context file parsing (CLAUDE.md, etc.)
- `generator.go` - Model generation from parsed data
- `validator.go` - Model validation

## Subpackages
- `../iac/` - Infrastructure as Code parsers
  - `terraform/` - Terraform parser
  - `kubernetes/` - Kubernetes manifest parser
  - `cloudformation/` - AWS CloudFormation parser