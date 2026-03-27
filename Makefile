.PHONY: up down build lint seed

run:
	docker compose up

down:
	docker compose down

build:
	docker compose build

lint:
	golangci-lint run ./...
