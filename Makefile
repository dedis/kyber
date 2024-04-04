.DEFAULT_GOAL := test

Coding/bin/Makefile.base:
	git clone https://github.com/dedis/Coding
include Coding/bin/Makefile.base

.PHONY: fetch-dependencies
fetch-dependencies:
	go get -v -t -d ./...