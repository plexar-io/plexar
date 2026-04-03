.PHONY: build run clean test fmt vet scan serve

BINARY := plexar
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOFLAGS := -ldflags="-s -w -X github.com/plexar-security/plexar/cmd.Version=$(VERSION) -X github.com/plexar-security/plexar/cmd.Commit=$(COMMIT) -X github.com/plexar-security/plexar/cmd.Date=$(DATE)"

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY) .

run: build
	./bin/$(BINARY)

scan: build
	./bin/$(BINARY) scan --namespace $(or $(NS),default)

serve: build
	./bin/$(BINARY) serve --namespace $(or $(NS),default) --ui --license-key=dev

clean:
	rm -rf bin/

test:
	go test -race -covermode atomic -coverprofile coverage.out ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

deps:
	go mod tidy

docker-build:
	docker build -t ghcr.io/plexar-security/plexar:$(VERSION) .
	docker tag ghcr.io/plexar-security/plexar:$(VERSION) ghcr.io/plexar-security/plexar:latest

docker-push: docker-build
	docker push ghcr.io/plexar-security/plexar:$(VERSION)
	docker push ghcr.io/plexar-security/plexar:latest
