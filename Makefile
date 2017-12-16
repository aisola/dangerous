# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

PACKAGE = github.com/aisola/dangerous

.PHONY: help
.DEFAULT_GOAL := help

test: ## Run go test
	go test ./...

fmt: ## Run go fmt linter
	go fmt ./...

cover: ## Run a coverage report
	go test -cover ./...

cover-html: ## Runs an html coverage report
	go test -coverprofile=cover.out .
	go tool cover -html=cover.out -o coverage.html

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'