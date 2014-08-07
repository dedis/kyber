#!/usr/local/bin/bash
# setup nodes after swapin

packages="golang git"

source config.sh

nodes="relay"
for i in $(seq 0 $maxclient); do
	nodes="$nodes client-$i"
done
for i in $(seq 0 $maxtrustee); do
	nodes="$nodes trustee-$i"
done

for n in $nodes; do
	# install packages we need
	ssh -o "StrictHostKeyChecking no" $n.lld.safer \
		sudo apt-get -y install $packages &
done
wait

