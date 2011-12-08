#!/usr/bin/python

import sys
import httplib

def main():

  if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s server port\n" % sys.argv[0])
    return

  server = sys.argv[1]
  port = int(sys.argv[2])

  print "=== Using server %s:%d ===" % (server, port)
  conn = httplib.HTTPConnection(server, port)
  
  print("Reading input from stdin...")
  data = sys.stdin.readlines()

  conn.request("POST", "/session/send", "\n".join(data), {"Accept": "text/plain"})

  resp = conn.getresponse()
  if resp.status == 200:
    print "OK!"
  else:
    print "Failed! %d %s" % (resp.status, resp.reason)

  print "Response: "
  print resp.read()
  print "=========================="

if __name__ == "__main__":
  main()
  
