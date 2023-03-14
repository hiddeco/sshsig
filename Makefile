COVERAGE_REPORT ?= coverage.out

all: fmt vet test

test:
	go test -v -race -coverprofile=$(COVERAGE_REPORT) ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

.PHONY: all test fmt vet
