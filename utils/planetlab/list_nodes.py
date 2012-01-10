#!/usr/bin/python
# Returns a list of all planetlab nodes
import Queue
import socket
import thread
import xmlrpclib

max_parallel = 64

class Parallel:
  def __init__(self):
    self.queue = Queue.Queue()
    self.waiting = 0

  def _wait(self, action, params):
    try:
      res = action(params)
      self.queue.put(res)
    except:
      self.queue.put(None)

  def add(self, action, params):
    self.waiting += 1
    thread.start_new_thread(self._wait, (action, params))

  def wait(self, timeout = None):
    try:
      res = self.queue.get(True, timeout)
    except:
      return None

    self.queue.task_done()
    self.waiting -= 1
    return res

f = file("nodes", "w+")

def wait(parallel):
  res = parallel.wait()
  if res != None:
    f.write(res + "\n")

api_server = xmlrpclib.ServerProxy('https://www.planet-lab.org/PLCAPI/', allow_none=True)
 
# Create an empty dictionary (XML-RPC struct)
auth = {"AuthMethod": "anonymous"}
 
all_nodes = api_server.GetNodes(auth, {}, ['hostname'])
 
parallel = Parallel()
# Create an array of string hostnames
node_hostnames = [node['hostname'] for node in all_nodes]
for node in node_hostnames:
  parallel.add(socket.gethostbyname, node)
  if parallel.waiting >= max_parallel:
    wait(parallel)

while parallel.waiting != 0:
  wait(parallel)

f.close()
