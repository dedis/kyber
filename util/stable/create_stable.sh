#!/usr/bin/env bash

set -e

main(){
    parse_args $@
    prepare_repo
    copy_stable
    copy_repo
    remove_files
    update_imports
}

show_help(){
    echo "
Syntax is: $0 [-ohv] stable_repo

Gets all stable code and puts it in a new repo.

    -h      help
    -v      verbose
    -o      overwrite
"
    exit 1
}

parse_args(){
    OPTIND=1
    overwrite=""
    verbose=0

    while getopts ":oh?v" opt; do
        case "$opt" in
        o)
            overwrite="yes"
            ;;
        h|\?)
            show_help
            exit 0
            ;;
        v)  verbose=1
            ;;
        esac
    done

    shift $((OPTIND-1))

    REPO=$1
}

prepare_repo(){
    if [ ! "$REPO" ]; then
        show_help
    fi

    REPOPATH="$GOPATH/src/$REPO"

    if [ -e "$REPOPATH" ]; then
        if [ "$overwrite" ]; then
            echo "Going to overwrite '$REPOPATH'"
            rm -rf "$REPOPATH"/*
        else
            echo "'$REPOPATH' exists - either delete it or use '-o'"
            exit 1
        fi
    fi
}

copy_stable(){
    if [ ! -f directories ]; then
        echo "Didn't find file 'directories' - so I don't know what to do."
        exit 1
    fi

    mkdir -p "$REPOPATH"
    local kyber=$( cd ../..; pwd )
    for d in $( cat directories ); do
        echo "Adding directory '$d' to stable"
        local kyberdir="$kyber/$d"
        local repodir="$REPOPATH/$d"
        mkdir -p "$repodir"
        if [ -d "$kyberdir" ]; then
            find "$kyberdir" -maxdepth 1 -type f | xargs -I {} cp {} "$repodir"
        else
            echo "Directory '$kyberdir' is not present - please update your directories-file. Aborting"
            exit 1
        fi
    done
}

copy_repo(){
    cp -av overwrite/* "$REPOPATH"
}

remove_files(){
    for f in $( cat remove_files ); do
        rm "$REPOPATH"/$f
    done
}

update_imports(){
    echo "updating imports"
    find "$REPOPATH" -name "*go" -exec perl -pi -e "s:github.com/dedis/kyber:$REPO:" "{}"
    find "$REPOPATH" -name "*go" -exec goimports -w "{}"
}

main $@
