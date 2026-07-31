.PHONY: install doctor validate test clean

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -e '.[dev]'

doctor:
	.venv/bin/lab doctor

validate:
	.venv/bin/lab config validate

test:
	.venv/bin/python -m pytest

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist

