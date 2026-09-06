.PHONY: install lint format typecheck test coverage db-upgrade db-downgrade run-api run-worker compose-up compose-down signatures-load demo

install:
	python3 -m venv .venv && .venv/bin/pip install -U pip
	.venv/bin/pip install -e ".[dev]"
	.venv/bin/playwright install chromium

lint:
	.venv/bin/ruff check api engine pipeline workers db tests
	.venv/bin/mypy api engine pipeline workers db

format:
	.venv/bin/ruff format api engine pipeline workers db tests
	.venv/bin/ruff check --fix api engine pipeline workers db tests

typecheck:
	.venv/bin/mypy api engine pipeline workers db

test:
	.venv/bin/pytest -q

coverage:
	.venv/bin/pytest tests/ --cov=engine --cov=pipeline --cov=api --cov=workers --cov=db --cov=config --cov=telemetry --cov-report=term

db-upgrade:
	.venv/bin/alembic upgrade head

db-downgrade:
	.venv/bin/alembic downgrade base

run-api:
	.venv/bin/uvicorn api.main:app --reload

run-worker:
	.venv/bin/celery -A workers.celery_app worker --loglevel=info

compose-up:
	docker compose up -d --wait

compose-down:
	docker compose down

signatures-load:
	.venv/bin/python -m db.load_signatures

demo:
	PYTHONPATH=. .venv/bin/python scripts/demo.py
