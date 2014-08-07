#!/usr/local/bin/bash
# setup nodes after swapin

packages="golang git"

source config.sh

# Start relay first
ssh relay.lld.safer pkill dissent
ssh relay.lld.safer go/src/dissent/main/dissent -relay &
sleep 2

# Start clients and trustees
for i in $(seq 0 $maxclient); do
	ssh client-$i.lld.safer pkill dissent
	ssh client-$i.lld.safer go/src/dissent/main/dissent -client=$i >client-$i.log &
done
for i in $(seq 0 $maxtrustee); do
	ssh trustee-$i.lld.safer pkill dissent
	ssh trustee-$i.lld.safer go/src/dissent/main/dissent -trustee=$i >trustee-$i.log &
done

