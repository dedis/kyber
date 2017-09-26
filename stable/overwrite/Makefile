all: test

# You can use `test_playground` to run any test or part of onet
# for more than once in Travis. Change `make test` in .travis.yml
# to `make test_playground`.
test_playground:
	cd network; \
	for a in $$( seq 10 ); do \
	  go test -v -race -short || exit 1 ; \
	done;

test_verbose:
	go test -v -race -short ./...

test_goveralls:
	${GOPATH}/bin/goveralls -service=travis-ci -race -show

test: test_goveralls
