PKG_TEST = gopkg.in/dedis/kyber.test
PKG_STABLE = gopkg.in/dedis/kyber.v1
CREATE_STABLE = $$GOPATH/src/github.com/dedis/Coding/bin/create_stable.sh -o stable

all: test

test_fmt:
	@echo Checking correct formatting of files
	@{ \
		files=$$( go fmt ./... ); \
		if [ -n "$$files" ]; then \
		echo "Files not properly formatted: $$files"; \
		exit 1; \
		fi; \
		if ! go vet ./...; then \
		exit 1; \
		fi \
	}

test_lint:
	@echo Checking linting of files
	@{ \
		go get -u github.com/golang/lint/golint; \
		lintfiles=$$( golint ./... ); \
		if [ -n "$$lintfiles" ]; then \
		echo "Lint errors:"; \
		echo "$$lintfiles"; \
		exit 1; \
		fi \
	}

# You can use `test_playground` to run any test or part of kyber
# for more than once in Travis. Change `make test` in .travis.yml
# to `make test_playground`.
test_playground:
	cd .; \
	for a in $$( seq 10 ); do \
	  go test -v -race -short || exit 1 ; \
	done;

test_verbose:
	go test -v -race -short ./...

test_goverall:
	${GOPATH}/bin/goveralls -service=travis-ci -race

test_stable_build:
	$(CREATE_STABLE) $(PKG_TEST)
	cd $$GOPATH/src/$(PKG_TEST); go build ./...

test_stable:
	$(CREATE_STABLE) $(PKG_TEST)
	cd $$GOPATH/src/$(PKG_TEST); make test

test: test_fmt test_lint test_goverall test_stable_build

create_stable:
	$(CREATE_STABLE) $(PKG_STABLE)
