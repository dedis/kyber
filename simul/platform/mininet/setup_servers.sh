#!/usr/bin/env bash
mininet="$(dirname ${BASH_SOURCE[0]})"
set -e

SERVER_GW="$1"
SERVERS="$@"
KEYS=/tmp/server_keys
SSH_TYPE="-t ssh-ed25519"
SSH_ID=~/.ssh/id_rsa
if [ -f /etc/issue ]; then
	echo Issue exists
	if grep -q "Debian.*7" /etc/issue; then
		SSH_TYPE=""
	fi
fi

if [ ! -f $SSH_ID ]; then
	echo "Creating global key"
	echo -e '\n\n\n\n' | ssh-keygen
fi

rm -f $KEYS
for s in $SERVERS; do
	echo Starting to install on $s
	login=root@$s
	ip=$( host $s | sed -e "s/.* //" )
	ssh-keygen -R $s > /dev/null || true
	ssh-keygen -R $ip  > /dev/null || true
	ssh-keyscan $SSH_TYPE $s >> ~/.ssh/known_hosts 2> /dev/null
	ssh-copy-id -f -i $SSH_ID $login &> /dev/null
	ssh $login "test ! -f .ssh/id_rsa && echo -e '\n\n\n\n' | ssh-keygen > /dev/null" || true
	ssh $login cat .ssh/id_rsa.pub >> $KEYS
	if ! ssh $login "egrep -q '(14.04|16.04|Debian GNU/Linux 8)' /etc/issue"; then
		clear
		echo "$s does not have Ubuntu 14.04, 16.04 or Debian 8 installed - aborting"
		exit 1
	fi
	scp $mininet/install_mininet.sh $login: > /dev/null
	if ! ssh $login which mn; then
		ssh -f $login "apt-get update"
		ssh -f $login "apt-get install -y psmisc"
		ssh -f $login "./install_mininet.sh > /dev/null" &
	else
		echo "Mininet already installed on $login"
	fi
done

DONE=0
NBR=$( echo $SERVERS | wc -w )
while [ $DONE -lt $NBR ]; do
	DONE=0
	clear
	echo "$( date ) - Waiting on $NBR servers - $DONE are done"
	for s in $SERVERS; do
		if ! ssh root@$s "ps ax | grep -v ps | grep install | grep -q mininet"; then
			DONE=$(( DONE + 1 ))
		else
			echo -e "\nProcesses on $s"
			ssh root@$s 'pstree -p $( ps ax | grep "bash ./install_mininet.sh" | grep -v grep | sed -e "s/ *\([0-9]*\) .*/\1/" )'
		fi
	done
	sleep 2
done

echo -e "\nAll servers are done installing - copying ssh-keys"

rm -f server_list
for s in $SERVERS; do
	login=root@$s
	cat $KEYS | ssh $login "cat - >> .ssh/authorized_keys"
	ip=$( host $s | sed -e "s/.* //" )
	ssh root@$SERVER_GW "ssh-keyscan $SSH_TYPE $s >> .ssh/known_hosts 2> /dev/null"
	ssh root@$SERVER_GW "ssh-keyscan $SSH_TYPE $ip >> .ssh/known_hosts 2> /dev/null"
	echo $s >> server_list
done

echo "Done installing to:"
cat server_list
rm $KEYS
