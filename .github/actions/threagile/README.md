# Threagile AI Threat Modeling Action

Automatically generate and validate threat models from your Infrastructure as Code (IaC) files using Threagile's AI-powered analysis.

## Features

- 🔍 **Automatic IaC Scanning**: Discovers and analyzes Terraform, Kubernetes, and CloudFormation files
- 🛡️ **Trust Boundary Detection**: Automatically identifies security boundaries from network topology
- 📊 **Risk Analysis**: Identifies and categorizes security risks in your infrastructure
- 💬 **PR Comments**: Provides detailed threat analysis directly in pull requests
- 🚦 **CI/CD Integration**: Fail builds based on risk thresholds

## Usage

### Basic Usage

```yaml
name: Threat Model Analysis
on: [pull_request]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Threagile Analysis
        uses: threagile/threagile-action@v1
        with:
          iac-dirs: 'terraform/,k8s/'
          comment-on-pr: true
```

### Advanced Usage

```yaml
name: Threat Model CI/CD
on:
  pull_request:
  push:
    branches: [main]

jobs:
  threat-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate and Analyze Threat Model
        id: threagile
        uses: threagile/threagile-action@v1
        with:
          mode: detailed
          iac-dirs: 'infrastructure/,kubernetes/,terraform/'
          output-file: 'threat-model.yaml'
          merge-with: 'existing-model.yaml'
          context-files: 'CLAUDE.md,.github/copilot-instructions.md'
          comment-on-pr: true
          fail-on-high-risk: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload Threat Model
        uses: actions/upload-artifact@v3
        with:
          name: threat-model
          path: |
            threat-model.yaml
            report.pdf
            risks.xlsx
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `mode` | Generation mode (`simple` or `detailed`) | No | `simple` |
| `iac-dirs` | Comma-separated directories containing IaC files | No | `.` |
| `output-file` | Output threat model file path | No | `threagile-generated.yaml` |
| `merge-with` | Existing threat model to merge with | No | - |
| `context-files` | AI context files (e.g., CLAUDE.md) | No | `CLAUDE.md,.github/copilot-instructions.md` |
| `comment-on-pr` | Comment analysis results on PR | No | `true` |
| `fail-on-high-risk` | Fail if high/critical risks found | No | `false` |
| `github-token` | GitHub token for PR comments | No | `${{ github.token }}` |
| `threagile-version` | Threagile version to use | No | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `risks-found` | Total number of risks identified |
| `high-risks` | Number of high/critical risks |
| `model-path` | Path to generated threat model |

## Examples

### Fail on High Risks

```yaml
- name: Threat Model with Risk Gate
  uses: threagile/threagile-action@v1
  with:
    fail-on-high-risk: true
```

### Custom IaC Directories

```yaml
- name: Scan Multiple IaC Sources
  uses: threagile/threagile-action@v1
  with:
    iac-dirs: 'aws/,azure/,k8s/deployments/'
```

### Merge with Existing Model

```yaml
- name: Update Existing Threat Model
  uses: threagile/threagile-action@v1
  with:
    merge-with: 'docs/threat-model.yaml'
    output-file: 'docs/threat-model.yaml'
```

### Use Specific Version

```yaml
- name: Use Specific Threagile Version
  uses: threagile/threagile-action@v1
  with:
    threagile-version: 'v1.2.3'
```

## PR Comment Example

When `comment-on-pr` is enabled, the action will post a detailed analysis:

```
## 🛡️ Threagile Threat Model Analysis

### Model Generation
- **Mode**: simple
- **IaC Directories**: terraform/,k8s/
- **Output**: threagile-generated.yaml

### Risk Summary
- **Total Risks**: 12
- **High/Critical Risks**: 3

#### Critical Risks
- **Unencrypted Data Store**: Database accepts unencrypted connections
- **Internet-Facing Admin Interface**: Administrative interface exposed to internet

#### High Risks
- **Missing Network Segmentation**: No network isolation between tiers

### Generated Files
- [Threat Model](threagile-generated.yaml)
- [Risk Report](report.pdf)
- [Risk Details](risks.xlsx)

⚠️ **Action Required**: Please review and address high/critical risks before merging.
```

## Supported IaC Formats

- **Terraform**: `.tf`, `.tf.json`, `.tfvars`
- **Kubernetes**: `.yaml`, `.yml` (with `apiVersion`)
- **CloudFormation**: `.yaml`, `.json` (coming soon)
- **AWS CDK**: TypeScript/Python (coming soon)
- **Helm Charts**: `Chart.yaml`, `values.yaml` (coming soon)

## Security Considerations

- The action only reads IaC files and never modifies them
- No credentials or secrets are extracted from your infrastructure
- All analysis is performed locally within your GitHub Actions runner
- Generated threat models can be reviewed before committing

## Troubleshooting

### No Risks Found

If no risks are identified:
1. Ensure IaC directories are correctly specified
2. Check that files have proper extensions
3. Verify IaC files contain actual resources

### Action Fails

If the action fails:
1. Check the logs for parsing errors
2. Ensure Threagile version is compatible
3. Verify file permissions in the repository

### PR Comments Not Appearing

If PR comments don't appear:
1. Ensure `github-token` has proper permissions
2. Verify the workflow runs on `pull_request` events
3. Check that `comment-on-pr` is set to `true`

## License

This action is part of the Threagile project and is licensed under the MIT License.