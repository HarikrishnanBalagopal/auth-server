# Make file for auth server

BINNAME     ?= auth-server
BINDIR      := $(CURDIR)/bin

GO_VERSION   ?= $(shell printf '1.19')
GOPATH        = $(shell go env GOPATH)
GOLANGCILINT  = $(GOPATH)/bin/golangci-lint

PKG        := ./...
LDFLAGS    := -w -s

SRC        = $(shell find . -type f -name '*.go' -print)
GIT_COMMIT = $(shell git rev-parse HEAD)
GIT_SHA    = $(shell git rev-parse --short HEAD)
GIT_TAG    = $(shell git tag --points-at | tail -n 1)
GIT_DIRTY  = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")

GOGET     := cd / && GO111MODULE=on go install 

ifdef VERSION
	BINARY_VERSION = $(VERSION)
endif
BINARY_VERSION ?= ${GIT_TAG}
ifneq ($(BINARY_VERSION),)
	LDFLAGS += -X github.com/konveyor/${BINNAME}/internal/common/version.version=${BINARY_VERSION}
	VERSION ?= $(BINARY_VERSION)
endif

VERSION ?= latest

VERSION_METADATA = unreleased
ifneq ($(GIT_TAG),)
	VERSION_METADATA =
endif
LDFLAGS += -X github.com/konveyor/${BINNAME}/internal/common/version.buildmetadata=${VERSION_METADATA}
LDFLAGS += -X github.com/konveyor/${BINNAME}/internal/common/version.gitCommit=${GIT_COMMIT}
LDFLAGS += -X github.com/konveyor/${BINNAME}/internal/common/version.gitTreeState=${GIT_DIRTY}
LDFLAGS += -extldflags "-static"

# Setting container tool
DOCKER_CMD := $(shell command -v docker 2> /dev/null)
PODMAN_CMD := $(shell command -v podman 2> /dev/null)

ifdef DOCKER_CMD
	CONTAINER_TOOL = 'docker'
else ifdef PODMAN_CMD
	CONTAINER_TOOL = 'podman'
endif

# HELP
# This will output the help for each task
.PHONY: help
help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# -- Build --

.PHONY: build
build: get $(BINDIR)/$(BINNAME) ## Build go code
	@printf "\033[32m-------------------------------------\n BUILD SUCCESS\n-------------------------------------\033[0m\n"

$(BINDIR)/$(BINNAME): $(SRC)
	go build -ldflags '$(LDFLAGS)' -o $(BINDIR)/$(BINNAME) .

.PHONY: get
get: go.mod
	go mod download

# -- Test --

.PHONY: test
test: ## Run tests
	go test -run . $(PKG) -race
	@printf "\033[32m-------------------------------------\n TESTS PASSED\n-------------------------------------\033[0m\n"

${GOTEST}:
	${GOGET} github.com/rakyll/gotest@v0.0.6

.PHONY: test-verbose
test-verbose: ${GOTEST}
	gotest -run . $(PKG) -race -v

${GOLANGCILINT}:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.45.2

.PHONY: test-style
test-style: ${GOLANGCILINT}
	${GOLANGCILINT} run --timeout 3m
	scripts/licensecheck.sh
	@printf "\033[32m-------------------------------------\n STYLE CHECK PASSED\n-------------------------------------\033[0m\n"

# -- CI --

.PHONY: ci
ci: clean build test test-style ## Run CI routine

# -- Release --

.PHONY: clean
clean:
	rm -rf $(BINDIR)/${BINNAME}
	go clean -cache

.PHONY: info
info: ## Get version info
	@echo "Version:           ${VERSION}"
	@echo "Git Tag:           ${GIT_TAG}"
	@echo "Git Commit:        ${GIT_COMMIT}"
	@echo "Git Tree State:    ${GIT_DIRTY}"

.PHONY: run
run:
	cd ./bin/test-auth && ../${BINNAME} --config auth-config.yaml


.PHONY: cbuild
cbuild:
	docker build -t quay.io/konveyor/auth-server:latest -f Dockerfile .
	docker tag quay.io/konveyor/auth-server:latest quay.io/konveyor/auth-server:${VERSION}
	docker tag quay.io/konveyor/auth-server:latest quay.io/hari_balagopal/auth-server:test-essen

.PHONY: cpush
cpush:
	docker push quay.io/hari_balagopal/auth-server:test-essen
