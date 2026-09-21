# Convenience targets for the SOC dashboard.
# Usage: make <target>

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help install dev generate validate run test cov verify smoke audit docker-build docker-run clean

help:            ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:         ## Create venv and install runtime dependencies
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -U pip
	$(BIN)/pip install -r requirements.txt

dev:             ## Install runtime + test/dev dependencies
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -U pip
	$(BIN)/pip install -r requirements-dev.txt

generate:        ## (Re)generate the offline sample dataset
	$(BIN)/python src/mock_data_generator.py

validate:        ## Pre-flight check a capture is metric-ready (e.g. SOURCE=suricata_eve PATH_=eve.json)
	$(BIN)/python src/validate_run.py --source $(or $(SOURCE),mock) $(if $(PATH_),--path $(PATH_),)

run:             ## Launch the dashboard (http://localhost:8501)
	$(BIN)/streamlit run src/app.py

test:            ## Run the test suite
	$(BIN)/python -m pytest

cov:             ## Run tests with a coverage report
	$(BIN)/python -m pytest --cov --cov-report=term-missing

smoke:           ## Smoke-test: import + render the dashboard once, fail on any exception
	$(BIN)/python -c "import sys; sys.path.insert(0, 'src'); \
	from streamlit.testing.v1 import AppTest; \
	at = AppTest.from_file('src/app.py', default_timeout=120).run(); \
	sys.exit('App raised: ' + str(at.exception[0]) if at.exception else print('OK: dashboard rendered, no exceptions.'))"

verify:          ## Full pre-publication check: lint + format + types + tests + app smoke
	$(BIN)/ruff check .
	$(BIN)/black --check .
	$(BIN)/mypy .
	$(BIN)/python -m pytest
	$(MAKE) smoke
	@echo "✓ verify: all gates passed — lint, format, types, tests, app smoke."

audit:           ## Scan pinned runtime deps for known CVEs (needs network; not in verify)
	$(BIN)/python -m pip install -q pip-audit
	$(BIN)/pip-audit -r requirements.txt --desc

docker-build:    ## Build the container image
	docker build -f docker/Dockerfile -t soc-dashboard:1.0.0 .

docker-run:      ## Run the container (http://localhost:8501)
	docker run --rm -p 8501:8501 soc-dashboard:1.0.0

clean:           ## Remove caches and generated data
	rm -rf src/__pycache__ tests/__pycache__ .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov data
