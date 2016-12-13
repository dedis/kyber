#!/usr/bin/env bash
# Source: https://github.com/h12w/gosweep/blob/master/gosweep.sh

DIR_SOURCE="$(find . -maxdepth 10 -type f -not -path '*/vendor*' -name '*.go' | xargs -I {} dirname {} | sort | uniq)"


BRANCH=$TRAVIS_PULL_REQUEST_BRANCH
echo "Using branch $BRANCH"

if [ "$TRAVIS_BUILD_DIR" ]; then
  cd $TRAVIS_BUILD_DIR
fi

# Run test coverage on each subdirectories and merge the coverage profile.
all_tests_passed=true

echo "mode: atomic" > profile.cov
for dir in ${DIR_SOURCE};
do
    go test -short -race -covermode=atomic -coverprofile=$dir/profile.tmp $dir

    if [ $? -ne 0 ]; then
        all_tests_passed=false
    fi
    if [ -f $dir/profile.tmp ]
    then
        cat $dir/profile.tmp | tail -n +2 >> profile.cov
        rm $dir/profile.tmp
    fi
done

if [[ $all_tests_passed = true ]];
then
    exit 0;
else
    exit 1;
fi
