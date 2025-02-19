tidy:
	go mod tidy

generate: tidy
	go generate ./...

# Coding style static check.
lint: tidy
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5
	golangci-lint run

vet: tidy
	go vet ./...

test: tidy
	go test ./...

coverage: tidy
	go test -json -covermode=count -coverprofile=profile.cov ./... > report.json

# target to run all the possible checks; it's a good habit to run it before
# pushing code
check: lint vet test
	echo "check done"
