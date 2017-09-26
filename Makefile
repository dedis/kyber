all: test

# It's most easy to update if we use v1, even for v1.2, v1.3...
PKG_STABLE = gopkg.in/dedis/onet.v1
include $(GOPATH)/src/github.com/dedis/Coding/bin/Makefile.base

# You can use `test_playground` to run any test or part of cothority
# for more than once in Travis. Change `make test` in .travis.yml
# to `make test_playground`.
test_playground:
	cd network; \
	for a in $$( seq 100 ); do \
	  go test -v -race -run ParallelStore || exit 1 ; \
	done;

# Other targets are:
# make create_stable
