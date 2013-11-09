#!/bin/bash
rm -f *log
./dissent server0.conf &> /dev/null &
pids=$!
./dissent server1.conf &> /dev/null &
pids="$pids $!"
./dissent server2.conf &> /dev/null &
pids=$"pids $!"
./dissent clients.conf

for pid in $pids; do
  echo $pid
  kill -KILL $pid
done
