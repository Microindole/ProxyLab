.PHONY: install doctor validate test clean

install:
	uv python install 3.12
	uv venv --python 3.12 .venv
	uv pip install --python .venv/bin/python -e '.[dev]'

doctor:
	.venv/bin/lab doctor

validate:
	.venv/bin/lab config validate

test:
	.venv/bin/python -m pytest

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist

