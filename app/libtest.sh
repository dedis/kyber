#!/usr/bin/env bash

# highest number of servers and clients
NBR=${NBR:-3}
# Per default, have $NBR servers
NBR_SERVERS=${NBR_SERVERS:-$NBR}
# Per default, keep one inactive server
NBR_SERVERS_GROUP=${NBR_SERVERS_GROUP:-$(( NBR_SERVERS - 1))}
# Show the output of the commands: 0=none, 1=test-names, 2=all
DBG_TEST=${DBG_TEST:-0}
# DBG-level for server
DBG_SRV=${DBG_SRV:-0}
# APPDIR is usually where the test.sh-script is located
APPDIR=${APPDIR:-$(pwd)}
# The app is the name of the builddir
APP=${APP:-$(basename $APPDIR)}
# Name of conode-log
COLOG=conode

RUNOUT=/tmp/run.out

startTest(){
    set +m
	if [ "$CLEANBUILD" ]; then
		rm -f conode $APP
	fi
	build $APPDIR
}

test(){
    cleanup
    echo "Testing $1"
    sleep .5
    test$1
}

testOK(){
    testOut "Assert OK for '$@'"
    if ! dbgRun "$@"; then
        fail "starting $@ failed"
    fi
}

testFail(){
    testOut "Assert FAIL for '$@'"
    if dbgRun "$@"; then
        fail "starting $@ should've failed, but succeeded"
    fi
}

testFile(){
    if [ ! -f $1 ]; then
        fail "file $1 is not here"
    fi
}

testNFile(){
    if [ -f $1 ]; then
        fail "file $1 IS here"
    fi
}

testFileGrep(){
	local G="$1" F="$2"
	testFile "$F"
	if ! pcregrep -M -q "$G" $F; then
		fail "Didn't find '$G' in file '$F': $(cat $F)"
	fi
}

testGrep(){
    S="$1"
    shift
    testOut "Assert grepping '$S' in '$@'"
    runOutFile "$@"
    doGrep "$S"
    if [ ! "$EGREP" ]; then
        fail "Didn't find '$S' in output of '$@': $GRP"
    fi
}

testNGrep(){
    G="$1"
    shift
    testOut "Assert NOT grepping '$G' in '$@'"
    runOutFile "$@"
    doGrep "$G"
    if [ "$EGREP" ]; then
        fail "DID find '$G' in output of '$@': $(cat $RUNOUT)"
    fi
}

testReGrep(){
	G="$1"
    testOut "Assert grepping again '$G' in same output as before"
    doGrep "$G"
    if [ ! "$EGREP" ]; then
        fail "Didn't find '$G' in last output: $(cat $RUNOUT)"
    fi
}

testReNGrep(){
	G="$1"
    testOut "Assert grepping again NOT '$G' in same output as before"
    doGrep "$G"
    if [ "$EGREP" ]; then
        fail "DID find '$G' in last output: $(cat $RUNOUT)"
    fi
}

doGrep(){
    WC=$( cat $RUNOUT | egrep "$1" | wc -l )
    EGREP=$( cat $RUNOUT | egrep "$1" )
}

testCount(){
    C="$1"
    G="$2"
    shift 2
    testOut "Assert counting '$C' of '$G' in '$@'"
    runOutFile "$@"
    doGrep "$G"
    if [ $WC -ne $C ]; then
        fail "Didn't find '$C' (but '$WC') of '$G' in output of '$@': $(cat $RUNOUT)"
    fi
}

testOut(){
    if [ "$DBG_TEST" -ge 1 ]; then
        echo -e "$@"
    fi
}

dbgOut(){
    if [ "$DBG_TEST" -ge 2 ]; then
        echo -e "$@"
    fi
}

dbgRun(){
    if [ "$DBG_TEST" -ge 2 ]; then
        OUT=/dev/stdout
    else
        OUT=/dev/null
    fi
    if [ "$OUTFILE" ]; then
        $@ 2>&1 | tee $OUTFILE > $OUT
    else
        $@ 2>&1 > $OUT
    fi
}

runGrepSed(){
	GREP="$1"
    SED="$2"
    shift 2
    runOutFile "$@"
    doGrep "$GREP"
    SED=$( echo $EGREP | sed -e "$SED" )
}

runOutFile(){
    OLDOUTFILE=$OUTFILE
    OUTFILE=$RUNOUT
    dbgRun "$@"
    OUTFILE=$OLDOUTFILE
}

fail(){
    echo
    echo -e "\tFAILED: $@"
    cleanup
    exit 1
}

backg(){
    ( $@ 2>&1 & )
}

build(){
	local builddir=$1
	local app=$( basename $builddir )
    if [ ! -e $app -o "$BUILD" ]; then
    	testOut "Building $app"
        if ! go build -o $app $builddir/*.go; then
            fail "Couldn't build $builddir"
        fi
    else
    	dbgOut "Not building $app because it's here"
    fi
}

buildDir(){
    BUILDDIR=${BUILDDIR:-$(mktemp -d)}
    mkdir -p $BUILDDIR
    cd $BUILDDIR
}

buildConode(){
	local incl="$@"
    local pkg=$( realpath $BUILDDIR | sed -e "s:$GOPATH/src/::" )
    local cotdir=$( mktemp -d )/conode
    mkdir -p $cotdir
    if [ ! "$incl" ]; then
    	incl=${APPDIR#$GOPATH/src/}/service
    fi

    ( echo -e "package main\nimport ("
    for i in $incl; do
    	echo -e "\t_ \"$i\""
    done
    echo ")" ) > $cotdir/import.go
    cat - > $cotdir/main.go << EOF
package main

import "github.com/dedis/onet/app"

func main(){
	app.Server()
}
EOF
	build $cotdir
	rm -rf $cotdir
	setupConode
}

setupConode(){
	# Don't show any setup messages
    DBG_OLD=$DBG_TEST
    DBG_TEST=0
	rm -f public.toml
    for n in $( seq $NBR_SERVERS ); do
        co=co$n
        rm -f $co/*
		mkdir -p $co
    	echo -e "127.0.0.1:200$(( 2 * $n ))\nCot-$n\n$co\n" | dbgRun runCo $n setup
    	if [ $n -le $NBR_SERVERS_GROUP ]; then
		    cat $co/public.toml >> public.toml
		fi
	done
    DBG_TEST=$DBG_OLD
}

runCoBG(){
    for nb in $@; do
    	testOut "starting conode-server #$nb"
    	( ./conode -d $DBG_SRV -c co$nb/private.toml | tee $COLOG$nb.log & )
    done
}

runCo(){
    local nb=$1
    shift
    testOut "starting conode-server #$nb"
    dbgRun ./conode -d $DBG_SRV -c co$nb/private.toml $@
}

cleanup(){
    pkill -9 conode 2> /dev/null
    pkill -9 $APP 2> /dev/null
    sleep .5
    rm -f co*/*bin
    rm -f cl*/*bin
}

stopTest(){
    cleanup
    if [ $( basename $BUILDDIR ) != build ]; then
        dbgOut "removing $BUILDDIR"
        rm -rf $BUILDDIR
    fi
    echo "Success"
}

if ! which pcregrep > /dev/null; then
	echo "*** WARNING ***"
	echo "Most probably you're missing pcregrep which might be used here..."
	echo "On mac you can install it with"
	echo -e "\n  brew install pcre\n"
	echo "Not aborting because it might work anyway."
	echo
fi

if ! which realpath > /dev/null; then
	echo "*** WARNING ***"
	echo "Most probably you're missing realpath which might be used here..."
	echo "On mac you can install it with"
	echo -e "\n  brew install coreutils\n"
	echo "Not aborting because it might work anyway."
	echo
	realpath() {
    	[[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
	}
fi

for i in "$@"; do
case $i in
    -b|--build)
    CLEANBUILD=yes
    shift # past argument=value
    ;;
    -nt|--notemp)
	BUILDDIR=$(pwd)/build
    shift # past argument=value
    ;;
esac
done
buildDir

export CONODE_SERVICE_PATH=$BUILDDIR/service_storage
