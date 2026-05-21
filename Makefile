.PHONY: run build test lint migrate-up migrate-down migrate-create docker-up docker-down docker-logs docker-rebuild

BINARY      := bin/api
PKG         := ./...
MIGRATIONS  := migrations
DB_DSN      ?= postgres://my_user:my_pass@localhost:5432/my_db?sslmode=disable

run:
	go run ./cmd/api

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/api

test:
	go test -race -count=1 $(PKG)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run

migrate-up:
	migrate -path $(MIGRATIONS) -database "$(DB_DSN)" up

migrate-down:
	migrate -path $(MIGRATIONS) -database "$(DB_DSN)" down 1

migrate-create:
	@test -n "$(name)" || { echo "usage: make migrate-create name=<migration_name>"; exit 1; }
	migrate create -ext sql -dir $(MIGRATIONS) -seq $(name)

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-rebuild:
	docker compose up -d --build
