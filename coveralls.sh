#!/usr/bin/env bash
# Source: https://github.com/h12w/gosweep/blob/master/gosweep.sh

DIR_EXCLUDE="$@"
DIR_SOURCE="$(find . -maxdepth 10 -type f -not -path '*/vendor*' -name '*.go' | xargs -I {} dirname {} | sort | uniq)"

if [ "$TRAVIS_BUILD_DIR" ]; then
  cd $TRAVIS_BUILD_DIR
fi

# Run test coverage on each subdirectories and merge the coverage profile.
all_tests_passed=true

echo "mode: atomic" > profile.cov
for dir in $DIR_SOURCE; do
	if ! echo $DIR_EXCLUDE | grep -q $dir; then
	    go test -short -race -covermode=atomic -coverprofile=$dir/profile.tmp $dir

    	if [ $? -ne 0 ]; then
        	all_tests_passed=false
    	fi
    	if [ -f $dir/profile.tmp ]; then
         	tail -n +2 $dir/profile.tmp >> profile.cov
        	rm $dir/profile.tmp
    	fi
    fi
done

if [ "$all_tests_passed" = true ]; then
    exit 0
else
    exit 1
fi
