#!/usr/bin/env bash

DBG_SRV=${DBG_SRV:-0}

runCoCfg(){
    echo -e "127.0.0.1:200$(( 2 * $1 ))\nNew Cothority $1\nco$1\n" | dbgRun runCo $1 setup
}

runCoBG(){
    nb=$1
    shift
    testOut "starting cothority-server #$nb"
#    ( ./cothority -d $DBG_SRV -c co$nb/config.toml $@ 2>&1 > /dev/null & )
    ( ./cothority -d $DBG_SRV -c co$nb/config.toml $@ & )
}

runCo(){
    nb=$1
    shift
    testOut "starting cothority-server #$nb"
    dbgRun ./cothority -d $DBG_SRV -c co$nb/config.toml $@
}

cothoritySetup(){
    DBG_OLD=$DBG_SHOW
    DBG_SHOW=0
    runCoCfg 1
    runCoCfg 2
    runCoCfg 3
    runCoBG 1
    runCoBG 2
    sleep 1
    cp co1/group.toml .
    tail -n 4 co2/group.toml >> group.toml
    DBG_SHOW=$DBG_OLD
}
