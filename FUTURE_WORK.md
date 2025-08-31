# Future Work Items - AI Integration

These items are to be completed after reboot:

## High Priority
1. **Implement proper HCL parser for Terraform** (currently using pattern matching)
2. **Implement detailed mode generator** with comprehensive analysis
3. **Implement model merge functionality** (currently stubbed)
4. **Complete context application logic** (more fields from CLAUDE.md)

## Medium Priority
5. **Add CloudFormation parser**
6. **Add Pulumi parser**
7. **Create advanced trust boundary detection algorithms**
8. **Implement model validation with rules engine**

## Lower Priority
9. **Add comprehensive integration tests**
10. **Create example projects and documentation**
11. **Test with real-world complex infrastructure**
12. **Add source code analysis for API endpoints**

## Current Status
- Phase 1 MVP is complete and pushed to GitHub
- All tests are passing
- Ready to continue with these Phase 2+ features after reboot

## In-Progress Items (Compilation Fixes Needed)
These items were started but need completion due to compilation errors:

### Kubernetes Parser Fixes
1. **Fix kubernetes parser compilation errors** - multiple undefined methods and field errors
2. **Implement missing converter methods** in kubernetes parser:
   - `workloadToContainer`
   - `serviceToLoadBalancer`
   - `ingressToLoadBalancer`
   - `pvcToStorage`
   - Helper functions: `extractContainerImage`, `extractStorageSize`

### Terraform Parser Fixes
3. **Fix terraform parser ParseResult field errors** - similar structure issues as kubernetes

### General Fixes
4. **Fix Metadata field initialization** in kubernetes and terraform parsers (use `ai.Metadata` type)
5. **Remove references to undefined fields** in ParseResult:
   - Remove uses of `TechnicalAssets`, `TrustBoundaries`, `Communications`, `DataAssets`
   - Use the correct fields: `Resources`, `Containers`, `LoadBalancers`, `Storages`, etc.
6. **Fix parser registration** - Update to use correct signature: `Register(name string, parser IaCParser)`

### Final Steps
7. **Run final build to verify all compilation errors are fixed**
8. **Test third-party license command** after build succeeds

## Notes
- The HCL and CloudFormation parsers were implemented with stub extraction methods
- Detailed mode generator was implemented but had type conversion issues (all fixed)
- Trust boundary detector was implemented with advanced algorithms
- All enum/type conversions have been fixed in the Go code
- License compatibility was verified and THIRD-PARTY-NOTICES.txt was created