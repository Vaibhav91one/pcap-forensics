SHELL := /bin/bash
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip
CAPTURE ?= captures/tls12-chacha20poly1305.pcap
OUT ?= out
FIXTURES := tests/fixtures

.DEFAULT_GOAL := help
.PHONY: help setup doctor fixtures captures lint format typecheck test verify analyze ciphers flows suites detectors regenerate clean distclean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Create the virtualenv and install the package with dev extras
	uv venv
	uv pip install -e '.[dev]'

doctor: ## Check that tshark, openssl and the package are usable
	$(PY) -m pcapforensics.cli doctor

fixtures: ## Regenerate the synthetic test fixtures
	$(PY) scripts/make_fixtures.py

captures: ## Download the public sample captures used for regression tests
	./scripts/fetch_captures.sh

lint: ## ruff
	.venv/bin/ruff check .

format: ## ruff --fix
	.venv/bin/ruff check --fix .

typecheck: ## mypy (strict)
	.venv/bin/mypy

test: ## Run the test suite
	$(PY) -m pytest -q

verify: lint typecheck test ## Everything CI runs

analyze: ## Full report for CAPTURE=... (default: a Wireshark sample)
	$(PY) -m pcapforensics.cli analyze $(CAPTURE) --out $(OUT)

ciphers: ## Crypto matrix for CAPTURE=...
	$(PY) -m pcapforensics.cli ciphers $(CAPTURE)

flows: ## Top conversations for CAPTURE=...
	$(PY) -m pcapforensics.cli flows $(CAPTURE)

suites: ## Dump the cipher-suite registry
	$(PY) -m pcapforensics.cli suites

detectors: ## List detectors
	$(PY) -m pcapforensics.cli detectors

regenerate: ## Rebuild data/cipher_suites.json from the vendored name table
	$(PY) scripts/gen_cipher_suites.py

clean: ## Remove caches and reports
	rm -rf $(OUT) .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

distclean: clean ## Also remove the virtualenv and the tshark pass cache
	rm -rf .venv
	rm -rf $${PCAP_DOCTOR_CACHE:-$${PCAP_FORENSICS_CACHE:-$$HOME/.cache/pcap-doctor}}
