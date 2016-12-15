#!/usr/bin/env bash

# highest number of servers and clients
NBR=${NBR:-3}
# Use for suppressing building if that directory exists
STATICDIR=${STATICDIR:-}
# If set, always build
BUILD=${BUILD:-}
# Show the output of the commands
DBG_SHOW=${DBG_SHOW:-0}

RUNOUT=/tmp/run.out

startTest(){
    set +m
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
    if [ "$DBG_SHOW" -ge 1 ]; then
        echo -e "$@"
    fi
}

dbgOut(){
    if [ "$DBG_SHOW" -ge 2 ]; then
        echo -e "$@"
    fi
}

dbgRun(){
    if [ "$DBG_SHOW" -ge 2 ]; then
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

cleanup(){
    pkill -9 cothorityd 2> /dev/null
    pkill -9 cosi 2> /dev/null
    pkill -9 ssh-ks 2> /dev/null
    sleep .5
    rm -f srv*/*bin
    rm -f cl*/*bin
}

stopTest(){
    cleanup
    if [ ! "$STATICDIR" ]; then
        echo "removing $DIR"
        rm -rf $DIR
    fi
    echo "Success"
}

if ! which pcregrep > /dev/null; then
	echo "*** WARNING ***"
	echo "Most probably you're missing pcregrep which might be used here..."
	echo "On mac you can install it with"
	echo "brew install pcre"
	echo "Not aborting because it might work anyway."
	echo
fi