# Mirqab Cloud Relay — Build & Deploy

.PHONY: build up down restart logs test lint validate deploy monitoring clean

# === Local Development ===

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down && docker compose up -d

logs:
	docker compose logs -f --tail=50

# === Monitoring ===

monitoring:
	docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

monitoring-down:
	docker compose -f docker-compose.yml -f docker-compose.monitoring.yml down

# === Testing ===

test:
	pytest tests/ -v --tb=short

lint:
	ruff check services/ tests/ --select E,F,W --ignore E501

# === Security ===

validate:
	bash scripts/validate-hardening.sh

secrets:
	bash scripts/generate-secrets.sh

tls-certs:
	bash scripts/generate-tls-certs.sh

# === VM Deployment ===

VM_HOST ?= 192.168.100.67
VM_USER ?= relay
VM_DIR  ?= ~/mirqab-cloud-relay

deploy:
	ssh $(VM_USER)@$(VM_HOST) "cd $(VM_DIR) && git pull && docker compose build && docker compose up -d"
	@echo "Waiting for services..."
	@sleep 10
	ssh $(VM_USER)@$(VM_HOST) "curl -sf http://localhost:8100/health && echo ' — API Gateway OK'"
	ssh $(VM_USER)@$(VM_HOST) "cd $(VM_DIR) && bash scripts/validate-hardening.sh"

deploy-monitoring:
	ssh $(VM_USER)@$(VM_HOST) "cd $(VM_DIR) && docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d prometheus grafana"

# === Cleanup ===

clean:
	docker compose down -v --remove-orphans
	docker image prune -f
