# AI Integration Refactoring Plan

Based on code review findings, here's a prioritized refactoring plan:

## Priority 1: Address Code Duplication (Week 1)

### 1.1 Extract Common Asset Converter
```go
// pkg/ai/converters/asset_converter.go
type AssetConverter interface {
    ToAsset(resource interface{}, sourceFile string) ai.TechnicalAsset
}

type AssetFactory struct {
    converters map[string]AssetConverter
    defaults   AssetDefaults
}
```

### 1.2 Centralize Trust Boundary Logic
```go
// pkg/ai/boundaries/manager.go
type BoundaryManager struct {
    DetectBoundaries(assets []TechnicalAsset) []TrustBoundary
    AssignAssets(boundaries []TrustBoundary, assets []TechnicalAsset)
}
```

### 1.3 Unified Communication Detector
```go
// pkg/ai/communications/detector.go
type CommunicationDetector interface {
    Detect(assets []TechnicalAsset) []CommunicationLink
}
```

## Priority 2: Complete Core Features (Week 2)

### 2.1 Implement Model Merge
- Use existing `pkg/input/model.go` Merge() function
- Add conflict resolution logic
- Enable --merge-with flag

### 2.2 Implement Proper Parsers
- Replace regex with `github.com/hashicorp/hcl/v2` for Terraform
- Use `k8s.io/apimachinery` for Kubernetes manifests
- Add error recovery and validation

### 2.3 Complete Context Application
- Full CLAUDE.md parsing
- Apply all context fields to model
- Support multiple context file formats

## Priority 3: Improve Architecture (Week 3)

### 3.1 Plugin-Based Parser Registration
```go
// pkg/ai/plugins/registry.go
type ParserPlugin interface {
    Parser
    Register() error
    Configure(config map[string]interface{})
}
```

### 3.2 Configuration-Driven Mappings
```yaml
# config/mappings.yaml
resources:
  aws_instance:
    technology: compute
    machine: virtual
    encryption: none
  aws_rds:
    technology: database
    machine: virtual
    encryption: aes256
```

### 3.3 Validation Framework
```go
// pkg/ai/validation/validator.go
type Validator struct {
    rules []ValidationRule
    Validate(model *types.Model) []ValidationResult
}
```

## Priority 4: Testing & Documentation (Week 4)

### 4.1 Unit Test Coverage
- Target: 80% coverage
- Focus on parser logic
- Mock external dependencies

### 4.2 Integration Tests
- End-to-end flow tests
- Multi-parser scenarios
- Error case coverage

### 4.3 Documentation
- API documentation
- Parser development guide
- Configuration reference

## Technical Debt Items

1. **Remove CloudFormation directory** if not implementing
2. **Standardize error handling** across all packages
3. **Consistent ID generation** patterns
4. **Proper logging** instead of fmt.Printf
5. **Configuration management** for defaults

## Migration Strategy

### Phase 1: Refactor Without Breaking Changes
- Extract interfaces
- Create adapters for existing code
- Add deprecation notices

### Phase 2: Migrate Parsers
- Update one parser at a time
- Maintain backward compatibility
- Add feature flags

### Phase 3: Remove Legacy Code
- Remove deprecated functions
- Clean up unused code
- Update documentation

## Success Metrics

- [ ] Code duplication < 10%
- [ ] Test coverage > 80%
- [ ] All TODOs resolved
- [ ] Consistent error handling
- [ ] Plugin architecture working
- [ ] Performance benchmarks passing

## Risks & Mitigations

**Risk**: Breaking existing functionality
**Mitigation**: Comprehensive test suite before refactoring

**Risk**: Scope creep
**Mitigation**: Strict adherence to phases

**Risk**: Performance regression
**Mitigation**: Benchmark tests for critical paths