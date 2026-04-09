GOPATH := $(shell go env GOPATH)
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

all: test

getdeps:
	@mkdir -p ${GOPATH}/bin
	@echo "Installing golangci-lint" && go install tool

lint: getdeps
	@echo "Running $@ check"
	@${GOPATH}/bin/golangci-lint run --build-tags kqueue --timeout=10m --config ./.golangci.yml

lint-fix: getdeps
	@echo "Running $@ check"
	@${GOPATH}/bin/golangci-lint run --build-tags kqueue --timeout=10m --config ./.golangci.yml --fix

test: lint
	@echo "Running unit tests"
	@go test -race -tags kqueue ./...
	@go test -tags kqueue,noasm ./...
	@go test -tags kqueue,purego ./...
	@go test -tags kqueue,nounsafe,noasm ./...

test-ldap: lint
	@echo "Running unit tests for LDAP with LDAP server at '"${LDAP_TEST_SERVER}"'"
	@go test -v -race ./ldap

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
