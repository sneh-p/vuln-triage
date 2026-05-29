# Makefile for Vulnerability Triage Co-Pilot

COMPOSE_FILE = compose/docker-compose.yaml

.PHONY: up
up:
	@echo "Starting services..."
	docker compose -f $(COMPOSE_FILE) up -d --build

.PHONY: down
down:
	@echo "Stopping services..."
	docker compose -f $(COMPOSE_FILE) down -v

.PHONY: logs
logs:
	docker compose -f $(COMPOSE_FILE) logs -f

.PHONY: migrate
migrate:
	@echo "Applying database migration..."
	docker compose -f $(COMPOSE_FILE) exec -T postgres psql -U triage_user -d vuln_triage < db/migrations/001_init.sql

.PHONY: seed
seed:
	@echo "Seeding database with assets and findings..."
	docker compose -f $(COMPOSE_FILE) exec -T postgres python -c "print('Seeding must be run on host or inside container')" || echo "Seeding script runs from host"

.PHONY: test
test:
	@echo "Running tests..."
	pytest tests/

.PHONY: brief
brief:
	@echo "Triggering daily brief dry-run..."
	docker compose -f $(COMPOSE_FILE) exec -T coordinator python agents/coordinator/app.py --once

.PHONY: tick
tick:
	@echo "Running one-off tick for all pipeline stages..."
	docker compose -f $(COMPOSE_FILE) exec -T ingestor python agents/ingestor/app.py --once
	docker compose -f $(COMPOSE_FILE) exec -T enricher python agents/enricher/app.py --once
	docker compose -f $(COMPOSE_FILE) exec -T correlator python agents/correlator/app.py --once
	docker compose -f $(COMPOSE_FILE) exec -T ticketer python agents/ticketer/app.py --once
