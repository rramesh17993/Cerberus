# 📋 SecureScan CLI Commands Reference

This document provides comprehensive reference for all SecureScan CLI commands and their usage.

## 🚀 Installation

```bash
# Install globally
npm install -g @securescan/cli

# Or install locally
cd cli
npm install
npm run build
npm link
```

## 🔧 Basic Usage

```bash
# Show help
securescan --help

# Show version
securescan --version

# Check for updates
securescan --check-updates
```

## 📚 Command Categories

### 🔐 Authentication Commands

#### `securescan auth login`
Login to SecureScan Platform

```bash
# Interactive login
securescan auth login

# Login with credentials
securescan auth login --email user@example.com --password mypassword

# Login with API key
securescan auth login --api-key sk_abc123...

# Set API endpoint and login
securescan auth login --api-url https://api.securescan.io --email user@example.com
```

**Options:**
- `-e, --email <email>` - Email address
- `-p, --password <password>` - Password
- `-k, --api-key <key>` - API key for authentication
- `-u, --api-url <url>` - API endpoint URL
- `--interactive` - Interactive login (default)

#### `securescan auth logout`
Logout from SecureScan Platform

```bash
# Logout completely
securescan auth logout

# Keep endpoint configuration
securescan auth logout --keep-config
```

#### `securescan auth status`
Check authentication status

```bash
# Show status
securescan auth status

# JSON output
securescan auth status --json
```

#### `securescan auth whoami`
Show current user information

```bash
securescan auth whoami
securescan auth whoami --json
```

#### `securescan auth key`
Manage API keys

```bash
# Generate new API key
securescan auth key generate --name "CI/CD Key" --expires 90

# List API keys
securescan auth key list

# Set API key
securescan auth key set sk_abc123...

# Revoke API key
securescan auth key revoke key-id-123
```

#### `securescan auth config`
Manage authentication configuration

```bash
# Set API endpoint
securescan auth config set-endpoint https://api.securescan.io

# Show configuration
securescan auth config show

# Reset configuration
securescan auth config reset
```

---

### 🔍 Scanning Commands

#### `securescan scan`
Execute security scans

```bash
# Scan current directory with all scanners
securescan scan

# Scan specific directory
securescan scan /path/to/project

# Scan with specific scanner types
securescan scan --type sast,sca,secrets

# Scan and save results
securescan scan --output results.json --format json

# Remote scan with project ID
securescan scan --project-id proj_123 --wait

# Local scan with Docker
securescan scan --local --type sast

# Scan with custom configuration
securescan scan --config custom-scan.yml
```

**Scanner Types:**
- `sast` - Static Application Security Testing (Semgrep)
- `sca` - Software Composition Analysis (Trivy)
- `dast` - Dynamic Application Security Testing (OWASP ZAP)
- `secrets` - Secret detection (Gitleaks)
- `iac` - Infrastructure as Code scanning (Checkov)
- `container` - Container image scanning (Trivy)
- `all` - All available scanners

**Options:**
- `-t, --type <types...>` - Scanner types to run
- `-o, --output <path>` - Output file path
- `-f, --format <format>` - Output format (json, sarif, html, csv)
- `-s, --severity <levels...>` - Filter by severity (low, medium, high, critical)
- `-e, --exclude <patterns...>` - Exclude patterns (glob)
- `-c, --config <path>` - Custom configuration file
- `-p, --project-id <id>` - Project ID for remote scanning
- `-w, --wait` - Wait for scan completion
- `--timeout <seconds>` - Scan timeout (default: 3600)
- `--no-parallel` - Disable parallel scanning
- `--local` - Force local scanning
- `--verbose` - Enable verbose output

#### `securescan scan status`
Check scan status

```bash
securescan scan status scan-id-123
```

#### `securescan scan list`
List recent scans

```bash
# List all scans
securescan scan list

# Filter by project
securescan scan list --project-id proj_123

# Limit results
securescan scan list --limit 5
```

#### `securescan scan cancel`
Cancel a running scan

```bash
securescan scan cancel scan-id-123
```

---

### 📁 Project Management Commands

#### `securescan project list`
List all projects

```bash
# List projects
securescan project list

# Search projects
securescan project list --search "web app"

# Filter by tags
securescan project list --tag frontend,react

# Filter by visibility
securescan project list --visibility private

# JSON output
securescan project list --json
```

**Options:**
- `-s, --search <query>` - Search by name or description
- `-t, --tag <tags...>` - Filter by tags
- `-v, --visibility <type>` - Filter by visibility (public/private)
- `-l, --limit <number>` - Number of results (default: 20)
- `--page <number>` - Page number
- `--json` - JSON output
- `--sort <field>` - Sort by field (name, created, updated)

#### `securescan project show`
Show project details

```bash
securescan project show proj_123
securescan project show proj_123 --json
```

#### `securescan project create`
Create a new project

```bash
# Interactive creation
securescan project create --interactive

# Quick creation
securescan project create --name "My App" --description "Web application" --repository https://github.com/user/app

# With settings
securescan project create \
  --name "My App" \
  --visibility private \
  --tags frontend,react,typescript
```

**Options:**
- `-n, --name <name>` - Project name
- `-d, --description <description>` - Project description
- `-r, --repository <url>` - Repository URL
- `--visibility <type>` - Visibility (public/private)
- `-t, --tags <tags...>` - Project tags
- `--interactive` - Interactive creation
- `--json` - JSON output

#### `securescan project update`
Update an existing project

```bash
# Interactive update
securescan project update proj_123 --interactive

# Update specific fields
securescan project update proj_123 --name "New Name" --description "Updated description"
```

#### `securescan project delete`
Delete a project

```bash
# With confirmation
securescan project delete proj_123

# Force delete
securescan project delete proj_123 --force
```

#### `securescan project set-default`
Set default project

```bash
# Interactive selection
securescan project set-default

# Specific project
securescan project set-default proj_123
```

#### `securescan project stats`
Show project statistics

```bash
# All projects
securescan project stats

# Specific project
securescan project stats proj_123

# JSON output
securescan project stats --json
```

---

### ⚙️ Configuration Commands

#### `securescan config show`
Show current configuration

```bash
# Show full configuration
securescan config show

# Show configuration file path
securescan config show --path

# JSON output
securescan config show --json
```

#### `securescan config set`
Set configuration values

```bash
# Set string value
securescan config set apiUrl "https://api.securescan.io"

# Set boolean value
securescan config set userPreferences.colorOutput true --type boolean

# Set number value
securescan config set scanDefaults.timeout 7200 --type number

# Set array value
securescan config set scanDefaults.scanners "sast,sca,secrets" --type array
```

**Types:**
- `string` - String value (default)
- `number` - Numeric value
- `boolean` - Boolean value (true/false)
- `array` - Comma-separated array

#### `securescan config defaults`
Manage scan defaults

```bash
# Interactive configuration
securescan config defaults set --interactive

# Set specific defaults
securescan config defaults set \
  --scanners sast,sca,secrets \
  --severity high,critical \
  --format sarif \
  --timeout 3600

# Show current defaults
securescan config defaults show

# Reset to factory defaults
securescan config defaults reset
```

#### `securescan config preferences`
Manage user preferences

```bash
# Interactive configuration
securescan config preferences set --interactive

# Set specific preferences
securescan config preferences set \
  --color true \
  --verbose false \
  --auto-update true

# Show current preferences
securescan config preferences show
```

#### `securescan config import`
Import configuration from file

```bash
# Replace configuration
securescan config import config.json

# Merge with existing
securescan config import config.json --merge

# Force import without validation
securescan config import config.json --force
```

#### `securescan config export`
Export configuration to file

```bash
# Export full configuration
securescan config export config.json

# Export without secrets
securescan config export config.json --no-secrets
```

#### `securescan config reset`
Reset configuration

```bash
# Reset all configuration
securescan config reset

# Keep authentication settings
securescan config reset --keep-auth

# Force reset without confirmation
securescan config reset --force
```

#### `securescan config wizard`
Interactive configuration wizard

```bash
securescan config wizard
```

---

## 🎯 Common Workflows

### 🚀 Getting Started

```bash
# 1. Configure CLI
securescan config wizard

# 2. Login to platform
securescan auth login

# 3. Create a project
securescan project create --interactive

# 4. Run your first scan
securescan scan --type all
```

### 🔄 CI/CD Integration

```bash
# 1. Generate API key
securescan auth key generate --name "CI/CD" --expires 365

# 2. Set API key in CI
export SECURESCAN_API_KEY="sk_abc123..."

# 3. Run scan in CI
securescan auth login --api-key $SECURESCAN_API_KEY
securescan scan --project-id $PROJECT_ID --wait --format sarif --output security-report.sarif
```

### 🏢 Team Setup

```bash
# 1. Set team API endpoint
securescan auth config set-endpoint https://securescan.company.com

# 2. Login with SSO
securescan auth login

# 3. Set team defaults
securescan config defaults set --scanners sast,sca,secrets --severity high,critical

# 4. Create team project
securescan project create --name "Team App" --visibility private --tags team,production
```

### 🔍 Local Development

```bash
# 1. Quick local scan
securescan scan --local --type sast,secrets

# 2. Save results for review
securescan scan --output daily-scan.json --format json

# 3. Generate HTML report
securescan scan --output report.html --format html
```

---

## 📊 Output Formats

### JSON Format
```json
{
  "summary": {
    "totalVulnerabilities": 5,
    "vulnerabilitiesBySeverity": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0
    }
  },
  "vulnerabilities": [...]
}
```

### SARIF Format
SARIF 2.1.0 compliant format for integration with code analysis tools.

### HTML Format
Interactive HTML report with charts and filtering capabilities.

### CSV Format
Comma-separated values for spreadsheet analysis.

---

## 🔧 Configuration File

The CLI stores configuration in `~/.securescan/config.json`:

```json
{
  "apiUrl": "https://api.securescan.io",
  "apiKey": "sk_...",
  "defaultProject": "proj_123",
  "scanDefaults": {
    "scanners": ["sast", "sca", "secrets"],
    "severity": ["medium", "high", "critical"],
    "format": "json",
    "timeout": 3600
  },
  "userPreferences": {
    "colorOutput": true,
    "verboseLogging": false,
    "autoUpdate": true
  }
}
```

---

## 🚨 Error Handling

The CLI provides comprehensive error handling with:

- **Exit codes** for CI/CD integration
- **Detailed error messages** with suggestions
- **Retry mechanisms** for network issues
- **Graceful fallbacks** for missing dependencies

### Common Exit Codes
- `0` - Success
- `1` - General error
- `2` - Authentication error
- `3` - Configuration error
- `4` - Scan error
- `5` - Network error

---

## 🔍 Troubleshooting

### Authentication Issues
```bash
# Check authentication status
securescan auth status

# Re-login
securescan auth logout
securescan auth login

# Verify API endpoint
securescan auth config show
```

### Scan Issues
```bash
# Check Docker availability (for local scans)
docker --version

# Run with verbose output
securescan scan --verbose

# Check configuration
securescan config show
```

### Configuration Issues
```bash
# Reset configuration
securescan config reset

# Run configuration wizard
securescan config wizard

# Show configuration file location
securescan config show --path
```

---

## 📚 Additional Resources

- **API Documentation**: [https://docs.securescan.io/api](https://docs.securescan.io/api)
- **Scanner Documentation**: [https://docs.securescan.io/scanners](https://docs.securescan.io/scanners)
- **CI/CD Integration**: [https://docs.securescan.io/cicd](https://docs.securescan.io/cicd)
- **GitHub Repository**: [https://github.com/securescan/framework](https://github.com/securescan/framework)

For support, please visit our [GitHub Issues](https://github.com/securescan/framework/issues) or contact [support@securescan.io](mailto:support@securescan.io).