.DEFAULT_GOAL := help
PY ?= python

.PHONY: help install test lint typecheck security audit docs serve docker all clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev + api extras
	$(PY) -m pip install -e ".[api,dev]"

test: ## Run the test suite
	$(PY) -m pytest -q

lint: ## Lint with ruff
	ruff check src tests

typecheck: ## Static type check with mypy
	mypy

security: ## Static security scan (bandit) + dependency audit (pip-audit)
	bandit -q -r src -c pyproject.toml
	pip-audit || true

docs: ## Regenerate the NIST control-mapping doc from the catalog
	$(PY) scripts/gen_nist_doc.py

serve: ## Run the API locally (dev)
	uvicorn mnemosyne.api.main:factory --factory --reload --port 8000

docker: ## Build the container image
	docker build -t mnemosyne-guard:local .

all: lint typecheck security test ## Run the full quality gate (what CI runs)

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
