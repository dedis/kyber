tidy:
	go mod tidy

generate: tidy
	go generate ./...

# Coding style static check.
lint: tidy
	# keep this in sync with .github/workflows/golangci-lint.yml
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1
	go mod tidy
	@echo "Run without flags"
	golangci-lint run
	@echo "Run with constantTime flag"
	golangci-lint run --build-tags=constantTime

test: tidy
	go test ./...

test-constantTime: tidy
	go test ./... --tags constantTime

test-all: test test-constantTime

coverage: tidy
	go test -json -covermode=count -coverprofile=profile.cov ./... > report.jsonl

# target to run all the possible checks; it's a good habit to run it before
# pushing code
check: lint test
	echo "check done"

build: tidy
	go build ./...
	go build -tags constantTime ./...
