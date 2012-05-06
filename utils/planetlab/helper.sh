#!/bin/bash
# A utility for setting up, running, and removing applications from PlanetLab

chmod +x $0
install_path=$2
install_file=data.tgz
app_name=$install_path/start.sh
user=$(whoami)

function running()
{
  if ! test  -f $install_path/pid; then
    return 0
  fi

  pid=$(cat $install_path/pid 2> /dev/null)

  if [[ $pid ]]; then
    on=$(ps uax | grep $pid | grep -v grep)
  fi

  if [[ $on ]]; then
    return 1
  else
    return 0
  fi
}

function md5_check()
{
  md5=$1
  if [[ $md5 == $(md5sum /home/$user/$install_file | awk '{print $1}') ]]; then
    return 1
  else
    return 0
  fi
}

function check()
{
  md5_check $1
  if [[ $? == 0 ]]; then
    echo "md5 check failed!"
    exit -1
  fi

  running
  if [[ $? == 0 ]]; then
    echo "is not running"
    exit -1
  fi
}

function setup()
{
  stop

  if ! test -f /home/$user/$install_file; then
    echo "no install file"
    exit -1
  fi

  md5_check $1
  if [[ $? == 0 ]]; then
    echo "md5 check failed"
    exit -1
  fi

  if test -d $install_path; then
    remove
  fi

  mkdir -p $install_path
  tar --overwrite --overwrite-dir -zxf /home/$user/$install_file -C $install_path &> /dev/null
  start
}

function remove()
{
  stop
  rm -rf $install_path
}

function start()
{
  if ! test -f $install_path/start.sh; then
    echo "start.sh not found in install path"
    exit -1
  fi

  bash $install_path/start.sh < /dev/null > /dev/null 2> /dev/null
}

function stop()
{
  running
  if [[ $? == 0 ]]; then
    return 0
  fi

  pid=$(cat $install_path/pid 2> /dev/null)

  # Test sudo
  sudo -S true < /dev/null &> /dev/null
  if [[ $? ]]; then
    sudo kill -KILL $pid 2> /dev/null
  else
    kill -KILL $pid 2> /dev/null
  fi
}

case "$1" in
  check)
    check ${@:3}
    ;;
  setup)
    setup ${@:3}
    ;;
  remove)
    remove ${@:3}
    ;;
  start)
    start ${@:3}
    ;;
  stop)
    stop ${@:3}
    ;;
  *)
    echo "usage: check, setup, remove, start, stop"
    ;;
esac
exit 0
