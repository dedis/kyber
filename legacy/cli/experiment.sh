# Easy version
# LD_LIBRARY_PATH=../libdissent ./cli -c test.conf -n 1 -s sk1.pem &
# LD_LIBRARY_PATH=../libdissent ./cli -c test.conf -n 2 -s sk2.pem &
# LD_LIBRARY_PATH=../libdissent ./cli -c test.conf -n 3 -s sk3.pem &

EXP=dissent-lan
MAX_NODE=`cat nnode`
INF=`cat infile`
LAST_INF=`cat last_infile`

# for ((i = 1; i <= $MAX_NODE; i++))
# do
#   ssh node-$i.$EXP.SAFER sudo apt-get update
#   ssh node-$i.$EXP.SAFER sudo apt-get install m2crypto python-numpy libqt4-core libqca2 libqca2-plugin-ossl
# done
for i in `seq 1 $MAX_NODE`;
do
  if [ $i == $MAX_NODE ];
  then
    BASH_ENV=~/.bashrc ssh node-$i.$EXP.SAFER \
      dissent/cli/cli -c $PWD/deter.conf -n $i -s dissent/keys/sk$i.pem \
      -q -r 1 -f tmp/$LAST_INF 2>&1 \
    | sed -u "s/^/$i: /" \
    | tee node-$i
  else
    BASH_ENV=~/.bashrc ssh node-$i.$EXP.SAFER \
      dissent/cli/cli -c $PWD/deter.conf -n $i -s dissent/keys/sk$i.pem \
      -q -r 1 -f tmp/$INF 2>&1 \
    | sed -u "s/^/$i: /" \
    | tee node-$i &
  fi
done

# to kill:
# for a in 1 2 3; do ssh node-$a.dissent-3.SAFER killall cli; done
