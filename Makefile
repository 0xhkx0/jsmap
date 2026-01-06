.PHONY: build test clean install run-test-server help

build:
@echo "Building jsmap..."
@go build -o jsmap ./cmd/jsmap

test:
@echo "Running tests..."
@cd cmd/jsmap && go test -v .

clean:
@echo "Cleaning up..."
@rm -f jsmap
@rm -f test/reports/*.html test/reports/*.json test/reports/*.csv

install: build
@echo "Installing jsmap..."
@cp jsmap $$(go env GOPATH)/bin/

run-test-server:
@echo "Starting test server on :3000..."
@go run test/testserver.go

help:
@echo "jsmap - JavaScript Security Scanner"
@echo ""
@echo "Targets:"
@echo "  build             Build the jsmap binary"
@echo "  test              Run tests"
@echo "  clean             Remove build artifacts"
@echo "  install           Install jsmap to GOPATH/bin"
@echo "  run-test-server   Start test HTTP server"
@echo "  help              Show this help message"
