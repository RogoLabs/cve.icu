# CVE.ICU Makefile
# Task runner for common build and development operations

.PHONY: help build quick test lint clean serve install

# Default target
help:
	@echo "CVE.ICU Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build     - Full site build (data + templates)"
	@echo "  quick     - Quick template-only build (no data regeneration)"
	@echo "  test      - Run test suite"
	@echo "  lint      - Run linters (flake8)"
	@echo "  clean     - Clean build artifacts"
	@echo "  serve     - Start local development server"
	@echo "  install   - Install Python dependencies"
	@echo ""
	@echo "Data rebuild targets:"
	@echo "  rebuild-cna    - Rebuild CNA analysis only"
	@echo "  rebuild-cpe    - Rebuild CPE analysis only"
	@echo "  rebuild-cvss   - Rebuild CVSS analysis only"
	@echo "  rebuild-cwe    - Rebuild CWE analysis only"
	@echo "  rebuild-growth - Rebuild growth analysis only"
	@echo "  rebuild-quality - Rebuild data quality analysis only"

# Install dependencies
install:
	pip install -r requirements.txt

# Full build
build:
	python build.py

# Quick template-only build
quick:
	python data/scripts/quick_build.py

# Run tests
test:
	python -m pytest tests/ -v

# Run tests with coverage
test-coverage:
	python -m pytest tests/ -v --cov=data --cov-report=term-missing

# Run linters
lint:
	python -m flake8 data/ --max-line-length=120 --ignore=E501,W503

# Clean build artifacts
clean:
	rm -rf web/*.html
	rm -rf web/data/*.json
	rm -rf __pycache__
	rm -rf data/__pycache__
	rm -rf data/scripts/__pycache__
	rm -rf tests/__pycache__
	rm -rf .pytest_cache
	rm -rf .coverage

# Start local development server
serve:
	@echo "Starting local server at http://localhost:8000"
	cd web && python -m http.server 8000

# Individual rebuild targets
rebuild-cna:
	python data/scripts/rebuild_cna.py

rebuild-cpe:
	python data/scripts/rebuild_cpe.py

rebuild-cvss:
	python data/scripts/rebuild_cvss.py

rebuild-cwe:
	python data/scripts/rebuild_cwe.py

rebuild-growth:
	python data/scripts/rebuild_growth.py

rebuild-quality:
	python data/scripts/rebuild_data_quality.py

# Rebuild all analysis files without full build
rebuild-all: rebuild-cna rebuild-cpe rebuild-cvss rebuild-cwe rebuild-growth rebuild-quality
	@echo "All analysis files rebuilt"

# Validate JSON schemas
validate:
	python -m pytest tests/test_schemas.py -v

# Development workflow: quick build + serve
dev: quick serve
