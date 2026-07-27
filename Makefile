.PHONY: lint format-check typecheck test check

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy src tests

test:
	uv run pytest

check: lint format-check typecheck test
