UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SED := $(shell command -v gsed 2>/dev/null)
    ifeq ($(SED),)
        $(error GNU sed (gsed) not found on macOS. \
			Install with: brew install gnu-sed)
    endif
else
    SED := sed
endif

.PHONY: help
help: ## Ask for help!
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Setup development environment
	python -m venv .venv
	.venv/bin/pip install -e ".[dev]"

.PHONY: install
install: ## Install the package
	pip install -e .

.PHONY: build
build: ## Build the package
	python -m build

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

.PHONY: format
format: ## Format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

.PHONY: check-format
check-format: ## Check code formatting
	ruff format --check src/ tests/
	ruff check src/ tests/

.PHONY: lint
lint: ## Run linter
	ruff check src/ tests/

.PHONY: typecheck
typecheck: ## Run type checker
	mypy src/

.PHONY: test
test: ## Run tests
	pytest tests/ -v

.PHONY: check
check: check-format lint typecheck ## Run all checks

.PHONY: run
run: ## Run the MCP server (requires LEAKIX_API_KEY env var)
	python -m leakix_mcp.server

.PHONY: fix-trailing-whitespace
fix-trailing-whitespace: ## Remove trailing whitespaces from all files
	@echo "Removing trailing whitespaces from all files..."
	@find . -type f \( \
		-name "*.py" -o -name "*.toml" -o -name "*.md" -o -name "*.yaml" \
		-o -name "*.yml" -o -name "*.json" \) \
		-not -path "./.venv/*" \
		-not -path "./.git/*" \
		-not -path "./dist/*" \
		-not -path "./build/*" \
		-exec sh -c \
			'$(SED) -i -e "s/[[:space:]]*$$//" "$$1"' \
			_ {} \; && \
		echo "Trailing whitespaces removed."

.PHONY: check-trailing-whitespace
check-trailing-whitespace: ## Check for trailing whitespaces in source files
	@echo "Checking for trailing whitespaces..."
	@files_with_trailing_ws=$$(find . -type f \( \
		-name "*.py" -o -name "*.toml" -o -name "*.md" -o -name "*.yaml" \
		-o -name "*.yml" -o -name "*.json" \) \
		-not -path "./.venv/*" \
		-not -path "./.git/*" \
		-not -path "./dist/*" \
		-not -path "./build/*" \
		-exec grep -l '[[:space:]]$$' {} + 2>/dev/null || true); \
	if [ -n "$$files_with_trailing_ws" ]; then \
		echo "Files with trailing whitespaces found:"; \
		echo "$$files_with_trailing_ws" | sed 's/^/  /'; \
		echo ""; \
		echo "Run 'make fix-trailing-whitespace' to fix automatically."; \
		exit 1; \
	else \
		echo "No trailing whitespaces found."; \
	fi
