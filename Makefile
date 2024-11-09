# Variables
PACKAGE_NAME = ducopy
PYTHON = python3
VENV = venv311
PYPI_REPO = pypi  # Use 'testpypi' for testing

# Commands
.PHONY: all install dev-install lint test build publish clean help increment-version

all: help

## Create a virtual environment and install dependencies
install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e .

## Install development dependencies
dev-install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e .[dev]

## Run linting with ruff and formatting with black
lint:
	$(VENV)/bin/ruff src/ tests/
	$(VENV)/bin/black src/ tests/

## Run tests with pytest
test:
	$(VENV)/bin/pytest

## Build the package for PyPI
build:
	rm -rf dist/
	$(VENV)/bin/python -m build

## Publish the package to PyPI (use PYPI_REPO variable to switch between pypi and testpypi)
## If AUTO_INCREMENT_VERSION is set, increment version before publishing
publish: $(if $(AUTO_INCREMENT_VERSION),increment-version) build
	$(VENV)/bin/python -m twine upload -r $(PYPI_REPO) dist/*

## Increment version number in pyproject.toml
increment-version:
	@echo "Incrementing version number in pyproject.toml..."
	@current_version=$$(grep -oP 'version = "\K[0-9]+' pyproject.toml); \
	new_version=$$((current_version + 1)); \
	sed -i "s/version = \"$$current_version\"/version = \"$$new_version\"/" pyproject.toml
	@echo "Version updated to $$new_version in pyproject.toml."

## Clean build artifacts
clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} +

## Display available commands
help:
	@echo "Commonly used make commands:"
	@echo "  make install                - Set up virtual environment and install the package"
	@echo "  make dev-install            - Set up environment with development dependencies"
	@echo "  make lint                   - Run ruff and black for linting and formatting"
	@echo "  make test                   - Run tests with pytest"
	@echo "  make build                  - Build the package for distribution"
	@echo "  make publish                - Publish the package to PyPI (or TestPyPI if PYPI_REPO is set to testpypi)"
	@echo "                              - Use AUTO_INCREMENT_VERSION=1 make publish to increment version before publishing"
	@echo "  make increment-version      - Manually increment the version number in pyproject.toml"
	@echo "  make clean                  - Clean build artifacts"

