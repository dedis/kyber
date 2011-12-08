#!/bin/bash
github_repo=github
wd=$PWD
rand=$RANDOM
git clone . /tmp/dissent.$rand
cd /tmp/dissent.$rand

function cleanup {
  echo $1
  cd $wd
  rm -rf /tmp/dissent.$rand
}

qmake test.pro
if test $? -ne 0; then
  cleanup "Error qmake test.pro"
  exit 1
fi

make -j8
if test $? -ne 0; then
  cleanup "Error make"
  exit 1
fi

./test --gtest_catch_exceptions=0
if test $? -ne 0; then
  cleanup "Error running test"
  exit 1
fi

qmake application.pro
if test $? -ne 0; then
  cleanup "Error qmake application.pro"
  exit 1
fi

make
if test $? -ne 0; then
  cleanup "Error make application.pro"
  exit 1
fi

cd $wd
git push $github_repo master
if ! test -d $wd/docs/html; then
  cleanup "All done!"
  exit 0
fi

cd /tmp/dissent.$rand
doxygen dissent.doxy >& /dev/null
rm -rf $wd/docs/html/*
cp -axf docs/html/* $wd/docs/html
cd $wd/docs/html
git add .
git commit -m "documentation update"
git push $github_repo gh-pages
cleanup
