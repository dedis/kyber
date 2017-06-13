#!/bin/bash -x

dfinityPath="$HOME/prog/dfinity/crypto"
dedisPath="$GOPATH/src/gopkg.in"
docker rm -f dfinity
docker run --rm -it --name dfinity -v $dfinityPath:/workspace -v $dedisPath:/workspace/go/src/gopkg.in dfinity/build 
