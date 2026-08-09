# ApexGuard — dev/test automation.
# Usage: make test  |  make lint  |  make proto  |  make build

SHELL := /bin/bash

.PHONY: help test lint proto build docker-up docker-down clean

help:
	@echo "targets:"
	@echo "  test        go build+vet+test (core, pulsefuzz) + pytest (shadownet, hexeye)"
	@echo "  lint        go vet + python compileall + yaml parse"
	@echo "  proto       buf generate (requires buf + protoc)"
	@echo "  build       docker compose build"
	@echo "  docker-up   docker compose -f deploy/docker-compose.yml up --build"
	@echo "  docker-down docker compose -f deploy/docker-compose.yml down"

test: go-test py-test

go-test:
	cd core && go build ./... && go vet ./... && go test -race ./...
	cd pulsefuzz && go build ./... && go vet ./... && go test -race ./...

py-test:
	python -m compileall -q shadownet hexeye
	python -m pytest shadownet/tests hexeye/tests -q

lint:
	cd core && go vet ./...
	cd pulsefuzz && go vet ./...
	python -m compileall -q shadownet hexeye
	python - <<'EOF'
import glob, yaml
files = [f for f in glob.glob("deploy/**/*.yml", recursive=True) + glob.glob("deploy/**/*.yaml", recursive=True)
         if "/templates/" not in f.replace("\\", "/")]
for f in files:
    with open(f) as fh:
        yaml.safe_load(fh)
    print("yaml ok:", f)
EOF

proto:
	buf lint && buf generate

build:
	docker compose -f deploy/docker-compose.yml build

docker-up:
	docker compose -f deploy/docker-compose.yml up --build

docker-down:
	docker compose -f deploy/docker-compose.yml down

clean:
	rm -rf core/bin pulsefuzz/bin apexconsole/dist kernelshield/agent/target hexeye/rust/target
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
