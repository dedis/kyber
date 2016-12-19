#!/usr/bin/env bash

DBG_SRV=${DBG_SRV:-0}
NBR_SERVERS=${NBR_SERVERS:-3}
COLOG=/tmp/cothority_

makeTestDir(){
    BUILDDIR=$(pwd)
    if [ "$STATICDIR" ]; then
        DIR=$STATICDIR
    else
        DIR=$(mktemp -d)
    fi
    mkdir -p $DIR
    cd $DIR
    echo "Building in $DIR"
    for n in $(seq $NBR_SERVERS); do
        co=co$n
        rm -f $co/*
        mkdir -p $co
    done
	build $GOPATH/src/github.com/dedis/cothority
	build $BUILDDIR
	APP=$(basename $BUILDDIR)
	cothoritySetup
}

cothoritySetup(){
    DBG_OLD=$DBG_SHOW
    DBG_SHOW=0
    runCoCfg 1
    runCoCfg 2
    runCoCfg 3
    cp co1/group.toml .
    tail -n 4 co2/group.toml >> group.toml
    DBG_SHOW=$DBG_OLD
}

testCothority(){
    runCoBG 1
    runCoBG 2
    sleep 1
    cp co1/group.toml testgroup.toml
    tail -n 4 co2/group.toml >> testgroup.toml
    testOK runCo 1 check -g testgroup.toml
    tail -n 4 co3/group.toml >> testgroup.toml
    testFail runCo 1 check -g testgroup.toml
}

runCoCfg(){
    echo -e "127.0.0.1:200$(( 2 * $1 ))\nNew Cothority $1\nco$1\n" | dbgRun runCo $1 setup
}

runCoBG(){
    local nb=$1
    shift
    testOut "starting cothority-server #$nb"
    ( ./cothority -d $DBG_SRV -c co$nb/config.toml $@ | tee $COLOG$nb.log & )
}

runCo(){
    local nb=$1
    shift
    testOut "starting cothority-server #$nb"
    dbgRun ./cothority -d $DBG_SRV -c co$nb/config.toml $@
}

build(){
	local appdir=$1
    local app=$(basename $appdir)
    if [ ! -e $app -o "$BUILD" ]; then
        if ! go build -o $app $appdir/*.go; then
            fail "Couldn't build $appdir"
        fi
    fi
}