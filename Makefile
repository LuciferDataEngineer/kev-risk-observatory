PYTHON ?= python3

.PHONY: test demo live

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

demo:
	PYTHONPATH=src $(PYTHON) -m kev_risk run --data-dir demo-data --as-of 2026-10-29 --kev-file tests/fixtures/kev.json --epss-file tests/fixtures/epss.csv

live:
	PYTHONPATH=src $(PYTHON) -m kev_risk run --data-dir data
