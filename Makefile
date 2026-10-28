.PHONY: setup tools test lint check baseline summary analysis clean

setup:            ## virtualenv + package with dev extras
	python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

tools:            ## scanners on macOS
	brew install syft grype trivy

test:
	pytest -q

lint:
	ruff check src tests analysis

check:            ## validate config and resolve every tag (no pulls)
	cvd check

baseline:         ## full scan for today
	cvd run

summary:
	cvd summary

analysis:         ## regenerate all figures
	python analysis/rq1_snapshot.py
	python analysis/rq2_variants.py
	python analysis/rq3_tags.py
	python analysis/rq4_churn_scanners.py

clean:
	rm -rf .pytest_cache .ruff_cache src/*.egg-info data/cache
