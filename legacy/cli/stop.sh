MAX_NODE=`cat nnode`
EXP=dissent-lan

for i in `seq 1 $MAX_NODE`;
do
  echo == $i ==
  ssh node-$i.$EXP.SAFER killall cli
done
