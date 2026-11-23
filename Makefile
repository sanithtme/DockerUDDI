.PHONY: install test lint clean
PY ?= python3

install:            ## editable install with dev tools
	$(PY) -m pip install -e ".[dev]"

test:               ## run the suite (stdlib unittest; pytest also works)
	cd tests && $(PY) -m unittest discover -s . -v

lint:
	ruff check src tests

clean:
	rm -rf state/* reports/* .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	touch state/.gitkeep reports/.gitkeep
