#!/bin/bash
# script checks wrongly formatted files using gofmt (http://golang.org/cmd/gofmt/)

fmtout=` go fmt ./...`
# if the output isn't empty exit with an error
if [ -z "$fmtout" ]; then
  exit 0;
else
  echo "File(s) not properly formatted:";
  echo "$fmtout";
  exit 1;
fi
