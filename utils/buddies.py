#!/usr/bin/python

import httplib
import json
import sys

def request(server, port, method, path):
  print "{:>4}: {:<15} | ".format(method, path)
  conn = httplib.HTTPConnection(server, port)
  conn.request(method, path)
  res = conn.getresponse()
  try:
    msg = json.loads(res.read())
    if not msg["buddies"]:
      print "Buddies not found!"
      return
    print "nyms:", msg["nyms"]
    print "members:", msg["members"]
  except:
    pass

def main():
  if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s server port\n" % sys.argv[0])
    return

  server = sys.argv[1]
  port = int(sys.argv[2])

  print "=== Using server %s:%d ===" % (server, port)
  request(server, port, "GET", "/session/buddies")

if __name__ == "__main__":
  main()
