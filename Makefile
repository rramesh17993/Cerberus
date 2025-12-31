# 📋 Makefile for SecureScan Framework
# Comprehensive development and deployment automation

.PHONY: help install dev test build deploy clean docs security-audit

# Default target
help: ## 📖 Show this help message
	@echo "🛡️  SecureScan Framework - Development Commands"
	@echo "================================================"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# 🏗️  SETUP & INSTALLATION
# =============================================================================

install: ## 🔧 Install all dependencies
	@echo "🔧 Installing dependencies..."
	@$(MAKE) install-backend
	@$(MAKE) install-frontend
	@$(MAKE) install-cli
	@$(MAKE) install-vscode-extension
	@echo "✅ All dependencies installed!"

install-backend: ## 🐍 Install backend dependencies
	@echo "🐍 Installing backend dependencies..."
	cd backend && python -m venv venv
	cd backend && source venv/bin/activate && pip install -r requirements.txt
	cd backend && source venv/bin/activate && pip install -r requirements-dev.txt

install-frontend: ## ⚛️ Install frontend dependencies
	@echo "⚛️ Installing frontend dependencies..."
	cd frontend && npm install

install-cli: ## 🖥️ Install CLI tool
	@echo "🖥️ Installing CLI tool..."
	cd cli && pip install -e .

install-vscode-extension: ## 🔌 Install VS Code extension dependencies
	@echo "🔌 Installing VS Code extension dependencies..."
	cd vscode-extension && npm install

# =============================================================================
# 🚀 DEVELOPMENT
# =============================================================================

dev: ## 🚀 Start all development services
	@echo "🚀 Starting development environment..."
	docker-compose up -d postgres redis
	@$(MAKE) migrate
	@echo "Starting services in background..."
	cd backend && source venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
	cd backend && source venv/bin/activate && celery -A app.workers.celery_app worker --loglevel=info &
	cd frontend && npm run dev &
	@echo "✅ All services started!"
	@echo "🌐 Dashboard: http://localhost:3000"
	@echo "📊 API Docs: http://localhost:8000/docs"

dev-backend: ## 🐍 Start backend development server
	@echo "🐍 Starting backend server..."
	cd backend && source venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend: ## ⚛️ Start frontend development server
	@echo "⚛️ Starting frontend server..."
	cd frontend && npm run dev

dev-worker: ## 👷 Start Celery worker
	@echo "👷 Starting Celery worker..."
	cd backend && source venv/bin/activate && celery -A app.workers.celery_app worker --loglevel=info

dev-flower: ## 🌸 Start Celery Flower (task monitor)
	@echo "🌸 Starting Celery Flower..."
	cd backend && source venv/bin/activate && celery -A app.workers.celery_app flower

# =============================================================================
# 🗄️ DATABASE
# =============================================================================

migrate: ## 🗄️ Run database migrations
	@echo "🗄️ Running database migrations..."
	cd backend && source venv/bin/activate && alembic upgrade head

migrate-create: ## 📝 Create new migration
	@echo "📝 Creating new migration..."
	@read -p "Migration message: " message; \
	cd backend && source venv/bin/activate && alembic revision --autogenerate -m "$$message"

migrate-reset: ## 🔄 Reset database (WARNING: destroys data)
	@echo "⚠️  WARNING: This will destroy all data!"
	@read -p "Are you sure? (y/N): " confirm; \
	if [ "$$confirm" = "y" ]; then \
		docker-compose down -v postgres; \
		docker-compose up -d postgres; \
		sleep 5; \
		$(MAKE) migrate; \
	fi

# =============================================================================
# 🧪 TESTING
# =============================================================================

test: ## 🧪 Run all tests
	@echo "🧪 Running all tests..."
	@$(MAKE) test-backend
	@$(MAKE) test-frontend
	@$(MAKE) test-cli
	@$(MAKE) test-integration
	@echo "✅ All tests completed!"

test-backend: ## 🐍 Run backend tests
	@echo "🐍 Running backend tests..."
	cd backend && source venv/bin/activate && pytest tests/ -v --cov=app --cov-report=html --cov-report=term

test-frontend: ## ⚛️ Run frontend tests
	@echo "⚛️ Running frontend tests..."
	cd frontend && npm test -- --coverage --watchAll=false

test-cli: ## 🖥️ Run CLI tests
	@echo "🖥️ Running CLI tests..."
	cd cli && python -m pytest tests/ -v

test-integration: ## 🔗 Run integration tests
	@echo "🔗 Running integration tests..."
	python scripts/run_integration_tests.py

test-e2e: ## 🎭 Run end-to-end tests
	@echo "🎭 Running E2E tests..."
	cd frontend && npm run test:e2e

test-watch: ## 👀 Run tests in watch mode
	@echo "👀 Running tests in watch mode..."
	cd backend && source venv/bin/activate && pytest-watch tests/

# =============================================================================
# 🏗️ BUILD & PACKAGE
# =============================================================================

build: ## 🏗️ Build all components
	@echo "🏗️ Building all components..."
	@$(MAKE) build-backend
	@$(MAKE) build-frontend
	@$(MAKE) build-cli
	@$(MAKE) build-vscode-extension
	@echo "✅ All components built!"

build-backend: ## 🐍 Build backend Docker image
	@echo "🐍 Building backend image..."
	docker build -t securescan/backend:latest -f backend/Dockerfile backend/

build-frontend: ## ⚛️ Build frontend
	@echo "⚛️ Building frontend..."
	cd frontend && npm run build

build-cli: ## 🖥️ Build CLI distribution
	@echo "🖥️ Building CLI distribution..."
	cd cli && python setup.py sdist bdist_wheel

build-vscode-extension: ## 🔌 Build VS Code extension
	@echo "🔌 Building VS Code extension..."
	cd vscode-extension && npm run compile && vsce package

# =============================================================================
# 🔍 CODE QUALITY
# =============================================================================

lint: ## 🔍 Lint all code
	@echo "🔍 Linting all code..."
	@$(MAKE) lint-backend
	@$(MAKE) lint-frontend
	@$(MAKE) lint-cli

lint-backend: ## 🐍 Lint backend code
	@echo "🐍 Linting backend..."
	cd backend && source venv/bin/activate && black app/ tests/ --check
	cd backend && source venv/bin/activate && flake8 app/ tests/
	cd backend && source venv/bin/activate && mypy app/

lint-frontend: ## ⚛️ Lint frontend code
	@echo "⚛️ Linting frontend..."
	cd frontend && npm run lint
	cd frontend && npm run type-check

lint-cli: ## 🖥️ Lint CLI code
	@echo "🖥️ Linting CLI..."
	cd cli && black securescan/ tests/ --check
	cd cli && flake8 securescan/ tests/

format: ## ✨ Format all code
	@echo "✨ Formatting all code..."
	cd backend && source venv/bin/activate && black app/ tests/
	cd backend && source venv/bin/activate && isort app/ tests/
	cd frontend && npm run format
	cd cli && black securescan/ tests/
	cd cli && isort securescan/ tests/

# =============================================================================
# 🔒 SECURITY
# =============================================================================

security-audit: ## 🔒 Run security audit
	@echo "🔒 Running security audit..."
	cd backend && source venv/bin/activate && safety check
	cd backend && source venv/bin/activate && bandit -r app/
	cd frontend && npm audit
	cd cli && safety check -r requirements.txt

security-scan: ## 🛡️ Run self-scan with SecureScan
	@echo "🛡️ Running self-scan..."
	securescan scan --path . --scanners semgrep,trivy,gitleaks --output json > security-report.json
	@echo "📊 Security report saved to security-report.json"

# =============================================================================
# 📚 DOCUMENTATION
# =============================================================================

docs: ## 📚 Generate documentation
	@echo "📚 Generating documentation..."
	cd backend && source venv/bin/activate && python scripts/generate_api_docs.py
	cd docs && mkdocs build

docs-serve: ## 📖 Serve documentation locally
	@echo "📖 Serving documentation..."
	cd docs && mkdocs serve

# =============================================================================
# 🚀 DEPLOYMENT
# =============================================================================

deploy-dev: ## 🧪 Deploy to development environment
	@echo "🧪 Deploying to development..."
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

deploy-staging: ## 🎭 Deploy to staging environment
	@echo "🎭 Deploying to staging..."
	kubectl apply -f infrastructure/kubernetes/staging/

deploy-prod: ## 🚀 Deploy to production environment
	@echo "🚀 Deploying to production..."
	@echo "⚠️  WARNING: This will deploy to production!"
	@read -p "Are you sure? (y/N): " confirm; \
	if [ "$$confirm" = "y" ]; then \
		kubectl apply -f infrastructure/kubernetes/production/; \
	fi

# =============================================================================
# 🐳 DOCKER OPERATIONS
# =============================================================================

docker-up: ## 🐳 Start Docker services
	@echo "🐳 Starting Docker services..."
	docker-compose up -d

docker-down: ## 🛑 Stop Docker services
	@echo "🛑 Stopping Docker services..."
	docker-compose down

docker-logs: ## 📜 View Docker logs
	@echo "📜 Viewing Docker logs..."
	docker-compose logs -f

docker-clean: ## 🧹 Clean Docker resources
	@echo "🧹 Cleaning Docker resources..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

# =============================================================================
# 🔧 UTILITIES
# =============================================================================

setup-env: ## 🔧 Setup environment variables
	@echo "🔧 Setting up environment variables..."
	python scripts/setup_environment.py

generate-secrets: ## 🔑 Generate secure secrets
	@echo "🔑 Generating secure secrets..."
	python scripts/generate_secrets.py

health-check: ## ❤️ Check service health
	@echo "❤️ Checking service health..."
	curl -f http://localhost:8000/health || echo "❌ Backend unhealthy"
	curl -f http://localhost:3000 || echo "❌ Frontend unhealthy"

demo: ## 🎬 Run demo scan
	@echo "🎬 Running demo scan..."
	securescan scan --path examples/vulnerable-app --scanners semgrep,trivy --output table

clean: ## 🧹 Clean all build artifacts
	@echo "🧹 Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "node_modules" -path "*/test/*" -exec rm -rf {} + 2>/dev/null || true
	rm -rf backend/htmlcov/ frontend/coverage/ cli/dist/ cli/build/
	@echo "✅ Cleanup completed!"

# =============================================================================
# 📊 MONITORING
# =============================================================================

monitor: ## 📊 Start monitoring stack
	@echo "📊 Starting monitoring stack..."
	docker-compose -f docker-compose.monitoring.yml up -d
	@echo "📈 Prometheus: http://localhost:9090"
	@echo "📊 Grafana: http://localhost:3001"

logs: ## 📜 Show application logs
	@echo "📜 Application logs..."
	docker-compose logs -f backend frontend worker

metrics: ## 📈 Show application metrics
	@echo "📈 Application metrics..."
	curl http://localhost:8000/metrics

# =============================================================================
# 🎯 EXAMPLES
# =============================================================================

example-scan: ## 🎯 Run example scan
	@echo "🎯 Running example scan..."
	securescan scan \
		--path examples/vulnerable-app \
		--scanners semgrep,trivy \
		--output json \
		--verbose

example-api: ## 🔌 Test API endpoints
	@echo "🔌 Testing API endpoints..."
	python scripts/test_api_examples.py

# =============================================================================
# 📦 RELEASE
# =============================================================================

release-patch: ## 🏷️ Create patch release
	@echo "🏷️ Creating patch release..."
	python scripts/bump_version.py patch

release-minor: ## 🏷️ Create minor release
	@echo "🏷️ Creating minor release..."
	python scripts/bump_version.py minor

release-major: ## 🏷️ Create major release
	@echo "🏷️ Creating major release..."
	python scripts/bump_version.py major

# Show system status
status: ## 📊 Show system status
	@echo "📊 System Status"
	@echo "==============="
	@echo "🐳 Docker:"
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep securescan || echo "No containers running"
	@echo ""
	@echo "🌐 Services:"
	@curl -s http://localhost:8000/health | jq . 2>/dev/null || echo "❌ Backend not responding"
	@curl -s http://localhost:3000 >/dev/null 2>&1 && echo "✅ Frontend running" || echo "❌ Frontend not responding"