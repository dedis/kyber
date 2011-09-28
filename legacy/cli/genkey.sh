MAX_NODE=50

for i in `seq 1 $MAX_NODE`;
do
  openssl genrsa -out sk$i.pem 2048
  openssl rsa -in sk$i.pem -pubout -out pk$i.pem
done
