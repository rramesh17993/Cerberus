# SecureScan Framework Testing

This directory contains comprehensive test suites for the SecureScan Framework.

## Test Structure

```
tests/
├── unit/              # Unit tests for individual components
│   ├── backend/       # Backend API tests
│   ├── frontend/      # Frontend component tests
│   └── cli/           # CLI command tests
├── integration/       # Integration tests
│   ├── api/           # API integration tests
│   ├── scanners/      # Scanner integration tests
│   └── e2e/           # End-to-end tests
├── fixtures/          # Test data and fixtures
│   ├── sample-code/   # Sample vulnerable code
│   ├── configs/       # Test configurations
│   └── reports/       # Sample reports
├── mocks/             # Mock implementations
└── helpers/           # Test utilities and helpers
```

## Test Categories

### Unit Tests
- **Backend**: FastAPI endpoints, database models, services
- **Frontend**: React components, utilities, API client
- **CLI**: Command execution, configuration, utilities

### Integration Tests
- **API**: Multi-endpoint workflows, authentication flows
- **Scanners**: Docker container execution, SARIF processing
- **Database**: Data persistence, migrations, queries

### End-to-End Tests
- **Complete Workflows**: Project creation to vulnerability reporting
- **Multi-Scanner**: Running multiple scanners on same project
- **CLI Integration**: Full CLI command sequences

## Running Tests

### Backend Tests
```bash
cd backend
pytest tests/ -v --cov=app
```

### Frontend Tests
```bash
cd frontend
npm test
npm run test:coverage
```

### CLI Tests
```bash
cd cli
npm test
npm run test:integration
```

### All Tests
```bash
# From project root
npm run test:all
```

## Test Data

### Sample Vulnerable Code
- **JavaScript**: XSS, CSRF, injection vulnerabilities
- **Python**: SQL injection, path traversal, insecure deserialization
- **Java**: Authentication bypasses, XXE, SSRF
- **Docker**: Misconfigured containers, security issues

### Test Configurations
- **Minimal**: Basic scanner configurations
- **Comprehensive**: Full feature testing
- **Custom**: Specific vulnerability patterns

## Performance Testing

### Load Testing
- **API Endpoints**: Concurrent request handling
- **Scanner Execution**: Multiple parallel scans
- **Database**: Query performance under load

### Stress Testing
- **Resource Limits**: Memory and CPU constraints
- **Concurrent Users**: Multiple simultaneous operations
- **Large Projects**: Scanning large codebases

## Security Testing

### Authentication Testing
- **JWT Validation**: Token expiration, tampering
- **API Key Management**: Creation, rotation, revocation
- **RBAC**: Role-based access control validation

### Input Validation
- **API Payloads**: Malformed requests, injection attempts
- **File Uploads**: Malicious file handling
- **CLI Arguments**: Command injection prevention

## Continuous Integration

### GitHub Actions
- **Pull Request**: Automated testing on PRs
- **Main Branch**: Full test suite execution
- **Release**: Extended testing with performance benchmarks

### Quality Gates
- **Code Coverage**: Minimum 80% coverage required
- **Security Scans**: No high/critical vulnerabilities
- **Performance**: Response time thresholds

## Test Environment Setup

### Docker Compose
```yaml
# docker-compose.test.yml
version: '3.8'
services:
  test-db:
    image: postgres:15
    environment:
      POSTGRES_DB: securescan_test
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
    ports:
      - "5433:5432"
  
  test-redis:
    image: redis:7-alpine
    ports:
      - "6380:6379"
```

### Environment Variables
```bash
# .env.test
DATABASE_URL=postgresql://test:test@localhost:5433/securescan_test
REDIS_URL=redis://localhost:6380
JWT_SECRET=test_secret_key
API_BASE_URL=http://localhost:8001
```

## Mock Data Generation

### Vulnerability Data
- **SARIF Files**: Valid SARIF 2.1.0 format
- **Scanner Outputs**: Realistic scanner results
- **False Positives**: Known false positive patterns

### Project Data
- **Repositories**: Git repositories with known vulnerabilities
- **Configurations**: Various project configurations
- **Dependencies**: Package files with vulnerable dependencies

## Test Utilities

### Database Helpers
```python
# tests/helpers/db.py
async def create_test_project():
    """Create a test project with sample data"""
    
async def clean_database():
    """Clean test database between tests"""
```

### API Helpers
```typescript
// tests/helpers/api.ts
export async function createAuthenticatedClient(): Promise<ApiClient>
export async function createTestProject(): Promise<Project>
```

### CLI Helpers
```typescript
// tests/helpers/cli.ts
export async function runCliCommand(command: string[]): Promise<CLIResult>
export async function setupTestConfig(): Promise<void>
```

## Reporting

### Coverage Reports
- **HTML Reports**: Detailed coverage visualization
- **Badge Generation**: Coverage badges for README
- **Trend Analysis**: Coverage change over time

### Test Results
- **JUnit XML**: CI/CD integration
- **JSON Reports**: Programmatic analysis
- **Screenshots**: Visual regression testing

## Best Practices

### Test Organization
1. **Arrange-Act-Assert**: Clear test structure
2. **Descriptive Names**: Self-documenting test names
3. **Single Responsibility**: One assertion per test
4. **Independent Tests**: No test dependencies

### Mock Strategy
1. **External Services**: Mock all external API calls
2. **File System**: Mock file operations in tests
3. **Time-based**: Mock time-dependent functionality
4. **Network**: Mock network requests

### Data Management
1. **Test Isolation**: Each test uses fresh data
2. **Cleanup**: Proper test teardown
3. **Reproducible**: Consistent test data
4. **Minimal**: Only necessary test data

## Debugging Tests

### Local Development
```bash
# Run single test with debugging
pytest tests/test_specific.py::test_function -v -s

# Run with debugger
pytest tests/test_specific.py --pdb

# Frontend debugging
npm test -- --watch --coverage=false
```

### CI Debugging
- **Artifact Collection**: Test logs and screenshots
- **Debug Mode**: Verbose logging enabled
- **Core Dumps**: Memory debugging for crashes

## Performance Benchmarks

### Response Times
- **API Endpoints**: < 500ms for standard operations
- **Scanner Execution**: Variable based on project size
- **Database Queries**: < 100ms for standard queries

### Resource Usage
- **Memory**: < 512MB for standard operations
- **CPU**: Efficient multi-core utilization
- **Disk**: Minimal temporary file usage

## Security Test Cases

### Authentication Flows
- Login/logout functionality
- Token refresh mechanisms
- Session management
- Multi-factor authentication

### Authorization Checks
- Resource access controls
- API endpoint permissions
- File system access
- Docker container isolation

### Input Validation
- SQL injection prevention
- XSS protection
- Command injection prevention
- File upload restrictions