#!/usr/bin/env bash

# Package installation
echo 'export LC_ALL="en_US.UTF-8"' >> /etc/environment
. /etc/environment
apt-get update
apt-get install -y screen rsync software-properties-common git vim cifs-utils pv htop mtr \
golang-1.6 aufs-tools ca-certificates xz-utils btrfs-tools \
debootstrap lxc rinse

# Configure ssh-port-forwarding
echo GatewayPorts yes >> /etc/ssh/sshd_config
/etc/init.d/ssh restart

# Mininet installation
git clone git://github.com/mininet/mininet
cd mininet
git checkout 2.2.1
./util/install.sh -a
