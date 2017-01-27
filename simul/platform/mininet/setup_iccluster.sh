#!/usr/bin/env bash
mininet="$(dirname ${BASH_SOURCE[0]})"

if [ -z "$1" ]; then
	echo "Syntax: $0 #1 #2 ..."
	echo "Will install mininet on servers iccluster0#1.iccluster.epfl.ch ..."
	exit 1
fi

ICCLUSTERS=""
for s in $@; do
  SERVER="iccluster0${s}.iccluster.epfl.ch"
  ICCLUSTERS="$ICCLUSTERS $SERVER"
done

"$mininet/setup_servers.sh" $ICCLUSTERS