tidy:
	#go install honnef.co/go/tools/cmd/staticcheck@latest
	go mod tidy

.PHONY: fetch-dependencies
fetch-dependencies:
	go get -v -t -d ./...

.PHONY: test
test: fetch-dependencies
	go test -v ./...
