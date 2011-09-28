for a in 4 8 12 16 20 24 28 32 36 40 44; do
  mkdir exp$a-v2
  cd exp$a-v2
  echo $a > nnode
  echo script > last_infile
  echo script > infile
  bash ../replay/genconf.sh 1 > deter.conf
  bash ../replay/experiment.sh
  sleep 60
  bash ../replay/stop.sh

  cd ..
done
