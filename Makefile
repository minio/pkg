GOPATH := $(shell go env GOPATH)
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

all: test

getdeps:
	@mkdir -p ${GOPATH}/bin
	@echo "Installing golangci-lint" && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin

lint: getdeps
	@echo "Running $@ check"
	@${GOPATH}/bin/golangci-lint cache clean
	@${GOPATH}/bin/golangci-lint run --build-tags kqueue --timeout=10m --config ./.golangci.yml

test: lint
	@echo "Running unit tests"
	@go test -race -tags kqueue ./...

test-ldap: lint
	@echo "Running unit tests for LDAP with LDAP server at '"${LDAP_TEST_SERVER}"'"
	@go test -v -race ./ldap

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
