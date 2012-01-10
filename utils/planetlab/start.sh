#!/bin/bash
# A utility for running applications on PlanetLab, in particular, this makes
# identifying an application easy, so that it can be killed (stopped) later.
app="dissent"
config="planetlab.config"

chmod +x $0
path=`which $0`
path=`dirname $path`

chmod +x $path/$app
chmod +x $path/cronolog

# clean up all previous running instances (just in case)
for pid in $(ps aux | grep $path/$app | grep -v grep | awk '{print $2}'); do
  kill -KILL $pid
done

$path/$app $path/$config 2>&1 | $path/cronolog --period="1 day" $path/log.%y%m%d.txt &
pid=$(ps uax | grep $path/$app | grep -v grep | awk '{print $2}')
echo $pid > $path/pid
