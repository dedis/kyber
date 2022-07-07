.DEFAULT_GOAL := test

.PHONY: fetch-dependencies
fetch-dependencies:
	go get -v -t -d ./...

.PHONY: test
test: fetch-dependencies
	go test -v ./...
