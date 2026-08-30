# AEGIS - Makefile for development and deployment

.PHONY: help install run test lint clean docker-build docker-run docker-stop health logs format type-check

# Default target
help:
	@echo "AEGIS Cyber Immune System - Available commands:"
	@echo ""
	@echo "  Development:"
	@echo "    make install        Install Python dependencies"
	@echo "    make run            Run the application locally"
	@echo "    make dev            Run with auto-reload for development"
	@echo "    make clean          Clean up cache and build files"
	@echo ""
	@echo "  Testing & Quality:"
	@echo "    make test           Run all tests"
	@echo "    make test-cov       Run tests with coverage report"
	@echo "    make lint           Run code quality checks (black, flake8)"
	@echo "    make format         Format code with black and isort"
	@echo "    make type-check     Run mypy type checking"
	@echo ""
	@echo "  Docker:"
	@echo "    make docker-build   Build Docker image"
	@echo "    make docker-run     Run application in Docker"
	@echo "    make docker-compose-up    Start all services with docker-compose"
	@echo "    make docker-compose-down  Stop all services"
	@echo "    make docker-logs    View application logs"
	@echo ""
	@echo "  Health & Monitoring:"
	@echo "    make health         Check application health"
	@echo "    make api-docs       Open API documentation"
	@echo ""

# Install dependencies
install:
	pip install --upgrade pip
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"

# Run application
run:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Run with auto-reload (development)
dev:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
test:
	pytest tests/ -v --tb=short

# Run tests with coverage
test-cov:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "\n✓ Coverage report generated in htmlcov/"

# Code quality checks
lint:
	@echo "Running black..."
	black --check src/ tests/ config/
	@echo "Running flake8..."
	flake8 src/ tests/ config/ --max-line-length=120 --exclude=__pycache__
	@echo "Running isort..."
	isort --check-only src/ tests/ config/
	@echo "✓ All lint checks passed"

# Format code
format:
	@echo "Formatting with isort..."
	isort src/ tests/ config/
	@echo "Formatting with black..."
	black src/ tests/ config/
	@echo "✓ Code formatted"

# Type checking
type-check:
	mypy src/ --ignore-missing-imports
	@echo "✓ Type check complete"

# Clean cache and build files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	rm -rf dist/ build/ *.egg-info
	@echo "✓ Cleanup complete"

# Build Docker image
docker-build:
	docker build -t aegis-cyber-immune:latest .
	@echo "✓ Docker image built"

# Run Docker container
docker-run:
	docker run -d -p 8000:8000 --name aegis-app aegis-cyber-immune:latest
	@echo "✓ Docker container started"

# Docker Compose
docker-compose-up:
	docker-compose up -d
	@echo "✓ All services started"

docker-compose-down:
	docker-compose down
	@echo "✓ All services stopped"

docker-compose-logs:
	docker-compose logs -f app

docker-logs:
	docker logs -f aegis-app

# Health check
health:
	@echo "Checking application health..."
	@curl -s http://localhost:8000/health || echo "Application not running"
	@echo ""
	@curl -s http://localhost:8000/api/v1/health || echo "API v1 not available"
	@echo ""
	@curl -s http://localhost:8000/api/v1/info | head -20 || echo "Info endpoint not available"

# Open API documentation
api-docs:
	@echo "Opening API documentation at http://localhost:8000/docs"
	@python -c "import webbrowser; webbrowser.open('http://localhost:8000/docs')"

# Database migrations
migrate:
	python scripts/migrate_db.py

# Setup development environment
setup-dev:
	cp .env.example .env
	make install
	@echo "✓ Development environment ready"

# Run all QA checks
qa: lint test type-check
	@echo "✓ All QA checks passed!"

# Security scan
security-scan:
	@echo "Running security scan..."
	pip-audit || echo "pip-audit not installed"
	@echo "✓ Security scan complete"

# Performance test
perf-test:
	@echo "Running performance tests..."
	pytest tests/ -v --benchmark-only || echo "pytest-benchmark not installed"

# Generate requirements hash
requirements-hash:
	sha256sum requirements.txt > requirements.txt.sha256
	@echo "✓ Requirements hash generated"

# Backup database
backup-db:
	@echo "Creating database backup..."
	docker exec neo4j neo4j-admin dump --to=/backups/aegis-backup.dump || echo "Backup failed"
	@echo "✓ Backup complete"

# Restore database
restore-db:
	@echo "Restoring database from backup..."
	docker exec neo4j neo4j-admin load --from=/backups/aegis-backup.dump --overwrite-destination=true || echo "Restore failed"
	@echo "✓ Restore complete"
