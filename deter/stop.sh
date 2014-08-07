#!/usr/local/bin/bash
# setup nodes after swapin

source config.sh

# Start relay first
ssh relay.lld.safer pkill dissent

# Start clients and trustees
#for i in $(seq 0 $maxclient); do
#	ssh client-$i.lld.safer pkill dissent
#done
#for i in $(seq 0 $maxtrustee); do
#	ssh trustee-$i.lld.safer pkill dissent
#done

