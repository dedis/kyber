#!/usr/bin/python
""" This application may seem like overkill.  Do not be fooled, reliabily
installing an application and starting it via ssh is no picnic.  To further
hamper the issue: PlanetLab is extremely unreliable and simple actions over a
network can take eons, if they even complete.  The purpose of this script is to
handle these issues as cleanly as possibly.  That is after execution, there
those nodes that could have the action performed were done so satisfactorily.
Those that could not did not leave stale ssh processes behind."""
usage = """usage:
Remoter --path_to_nodes=<filename> [--username=<username>]
  [--ssh_key=<filename>] [--data_file=<filename>] [--install_path=<path>]
  [--data_path=<path>] action
action = check, install, uninstall, gather_stats, gather_logs, uptime (check
  attempts to add the boot strap software to nodes that do not have it yet...
  a common problem on planetlab)
path_to_nodes = a file containing a new line delimited file containing hosts
  to perform the specified action on.
username = the user name for the hosts (defaults to current user)
ssh_key = path to the ssh key to be used (defaults to what is preloaded)
data_file = the file (tgz) to copy to the remote hosts for installation
install_path = the path on a remote host to extract the data_file
data_path = location in the local machine to store retrieved data (default = .)
"""

import getopt
import getpass
import hashlib
import os
import Queue
import re 
import signal
import shutil
import subprocess
import sys 
import thread
import time
import traceback
import xmlrpclib

parallel = 128
max_wait = 240

def main():
  optlist, args = getopt.getopt(sys.argv[1:], "", ["data_file=", \
    "username=", "path_to_nodes=", "ssh_key=", "install_path=", "data_path="])

  o_d = {}
  for k,v in optlist:
    o_d[k] = v

  if len(args) == 0:
    print "\nNo action"
    print_usage()

  action = args[0]
  if action not in ["check", "install", "uninstall", "gather_logs", "uptime"]:
    print "\nNo such action: " + action
    print_usage()

  if "--path_to_nodes" in o_d:
    try:
      nodes = []
      nodes_file = o_d["--path_to_nodes"]
      f = open(nodes_file)
      line = f.readline()
      nodes.append(line.rstrip('\n\r '))
      for line in f:
        nodes.append(line.rstrip('\n\r '))
      f.close()
    except:
      print "\nError in parsing path_to_nodes"
      print_usage()
  else:
    print "\nMissing required parameter: path_to_nodes"
    print_usage()

  username = None
  if "--username" in o_d:
    username = o_d["--username"]
  else:
    username = getpass.getuser()

  ssh_key = None
  if "--ssh_key" in o_d:
    ssh_key = o_d["--ssh_key"]

  data_file = None
  if "--data_file" in o_d:
    data_file = o_d["--data_file"]
    if not os.path.isfile(data_file):
      print "\nCannont find file: " + data_file
      print_usage()

  install_path = None
  if "--install_path" in o_d:
    install_path = o_d["--install_path"]

  data_path = "."
  if "--data_path" in o_d:
    data_path = o_d["--data_path"]

  plab = Remoter(action, nodes, username, ssh_key, data_file = data_file, \
      install_path = install_path, data_path = data_path)
  plab.run()

def print_usage():
  print usage
  os._exit(0)

def logger_std_out(text):
  print(text)

class ParallelWait:
  def __init__(self):
    self.pids = {}
    self.queue = Queue.Queue()

  def _wait(self, pid):
    try:
      res = os.waitpid(pid, 0)
      self.queue.put((pid, res[1]))
    except:
      self.queue.put((pid, -1))

  def add(self, pid, description = None):
    self.pids[pid] = (time.time(), description)
    thread.start_new_thread(self._wait, (pid, ))

  def wait(self, timeout = None):
    try:
      res = self.queue.get(True, timeout)
    except:
      return None

    self.queue.task_done()
    del self.pids[res[0]]
    return res

class Remoter:
  def __init__(self, action, nodes, username, ssh_key = None, \
      install_path = None, data_file = None, data_path = ".",
      logger = logger_std_out):

    self.action = action
    self.username = username
    self.nodes = nodes
    self.install_path = install_path
    self.data_file = data_file
    self.data_path = data_path
    self.logger = logger
    self.update_callback = None

    if self.data_file:
      df = open(self.data_file)
      md5 = hashlib.md5()
      md5.update(df.read())
      self.md5sum = md5.hexdigest()
      df.close()

    ssh_ops = "-o StrictHostKeyChecking=no -o HostbasedAuthentication=no " + \
        "-o CheckHostIP=no -o ConnectTimeout=10 -o ServerAliveInterval=30 " + \
        "-o BatchMode=yes -o UserKnownHostsFile=/dev/null "

    if ssh_key != None:
      ssh_ops += "-o IdentityFile=" + ssh_key + " "

    self.base_ssh_cmd = "/usr/bin/ssh " + ssh_ops + username + "@"
    self.base_scp_cmd = "/usr/bin/scp " + ssh_ops

    if action == "install":
      self.task = self.install_node
    elif action == "check":
      self.task = self.check_node
    elif action == "uninstall":
      self.task = self.uninstall_node
    elif action == "gather_logs":
      self.task = self.gather_logs
      self.log_path = "%s/logs" % (self.data_path,)
      if os.path.exists(self.log_path):
        shutil.rmtree(self.log_path)
      os.makedirs(self.log_path)
    elif action == "uptime":
      self.task = self.cmd
      self.args = "uptime"
      os.system("rm -rf cmd")
      os.system("mkdir cmd")
    elif action == "ls":
      self.task = self.cmd
      self.args = "ls -al"
      os.system("rm -rf cmd")
      os.system("mkdir cmd")
    elif action == "ps":
      self.task = self.cmd
      self.args = "ps uax"
      os.system("rm -rf cmd")
      os.system("mkdir cmd")
    else:
      "Invalid action: " + action
      print_usage()


# Runs #parallel threads at the same time, this works well because half of the
# nodes contacted typically are unresponsive and take tcp time out to fail or
# in other cases, they are bandwidth limited while downloading the data for
# install
  def run(self):
    # process each node
    waiter = ParallelWait()
    for node in self.nodes:
      if len(waiter.pids) >= parallel:
        waiter.wait()

      pid = os.fork()
      if pid == 0:
        self.task(node)
        os._exit(0)

      waiter.add(pid, node)

    while len(waiter.pids) != 0:
      if waiter.wait(max_wait / 5) != None:
        continue

      now = time.time()
      for pid, stime_des in waiter.pids.items():
        if now - stime_des[0] > max_wait:
          print "Killing action on %s[%s] for taking too long" % \
              (stime_des[1], pid)
          os.kill(pid, signal.SIGKILL)

  def check_node(self, node):
    cmd = "%s helper.sh %s@%s:/home/%s/helper.sh &> /dev/null" % \
        (self.base_scp_cmd, self.username, node, self.username)
    os.system(cmd)

    self.node_install(node, True)

  def install_node(self, node):
    self.node_install(node, False)

  # node is the hostname that we'll be installing the software stack unto
  # check determines whether or not to check to see if software is already
  #   running and not install if it is.
  def node_install(self, node, check):
    cmd = "%s helper.sh %s@%s:/home/%s/helper.sh &> /dev/null" % \
        (self.base_scp_cmd, self.username, node, self.username)
    os.system(cmd)

    base_ssh = self.base_ssh_cmd + node + " "
    if check:
        # This prints something if all is good ending this install attempt
      res = ssh_cmd("%s bash /home/%s/helper.sh check %s %s" % (base_ssh, \
          self.username, self.install_path, self.md5sum), self.logger)

      if res == "":
        self.logger(node + " no state change...")
        return

    # this helps us leave early in case the node is inaccessible
    cmd = "%s %s %s@%s:/home/%s/data.tgz &> /dev/null" % (self.base_scp_cmd, \
        self.data_file, self.username, node, self.username)
    os.system(cmd)
    res = ssh_cmd("%s bash /home/%s/helper.sh setup %s %s" % (base_ssh, \
        self.username, self.install_path, self.md5sum), self.logger)

    if res == "":
      self.logger(node + " done!")
      if self.update_callback:
        self.update_callback(node, 1)
    else:
      self.logger(node + " failed!" + " " + res)
      if self.update_callback:
        self.update_callback(node, 0)
    return

  def uninstall_node(self, node):
    cmd = "%s helper.sh %s@%s:/home/%s/helper.sh &> /dev/null" % \
        (self.base_scp_cmd, self.username, node, self.username)
    os.system(cmd)

    base_ssh = self.base_ssh_cmd + node + " "
    res = ssh_cmd("%s bash /home/%s/helper.sh remove %s" % (base_ssh, \
        self.username, self.install_path), self.logger)

    if res == "":
      if self.update_callback:
        self.update_callback(node, 0)
      else:
        self.logger(node + " done!")
    else:
      if self.update_callback:
        self.update_callback(node, 1)
      else:
        self.logger(node + " failed!")

  def gather_logs(self, node):
    os.mkdir("%s/%s" % (self.log_path, node))
    cmd = "%s %s@%s:%s/log.* %s/logs/%s/. &> /dev/null" % \
        (self.base_scp_cmd, self.username, node, self.install_path, \
        self.data_path, node)
    os.system(cmd)
    return

  def cmd(self, node):
    cmd = "%s%s %s 2> /dev/null 1> cmd/%s" % (self.base_ssh_cmd, node, self.args, node)
    os.system(cmd)
    return
    try:
      os.system(cmd)
    except:
      pass
    return
    
# This runs the ssh command monitoring it for any possible failures and raises
# an the KeyboardInterrupt if there is one.
def ssh_cmd(cmd, logger = logger_std_out):
  cmd = cmd + " 0<&-"
  p = subprocess.Popen(cmd.split(' '), stdin=subprocess.PIPE, \
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  p.stdin.close()
  os.waitpid(p.pid, 0)
  err = p.stderr.read()
  out = p.stdout.read()
  good_err = re.compile("Warning: Permanently added")
  if good_err.search(err) != None:
    nerr = ''
    for line in err.split('\n'):
      if good_err.search(line) != None:
        continue
      nerr += line + "\n"
    err = nerr
  err = err.strip()
  out = out.strip()

#  if err != "":
#    logger("err: " + err)
#  if out != "":
#    logger("out: " + out)
  if err != '':
    return err
  return out

if __name__ == "__main__":
  main()
