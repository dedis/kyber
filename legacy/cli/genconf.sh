MAX_NODE=`cat nnode`
PORT=`expr 10000 + $RANDOM % 10000`

for i in `seq 1 $MAX_NODE`;
do
  echo node$i=/users/$USER/dissent/keys/pk$i.pem:node-$i:$PORT
done
echo protocol_version=version_1
