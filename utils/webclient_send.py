#!/usr/bin/python

import sys
import httplib

def send(ip, port, msg):
  conn = httplib.HTTPConnection(ip, port)
  conn.request("POST", "/session/send", msg, {"Accept": "text/plain"})
  return conn.getresponse()

def main():
  if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s ip port\n" % sys.argv[0])
    return

  ip = sys.argv[1]
  port = int(sys.argv[2])

  print "=== Using server %s:%d ===" % (ip, port)
  print("Reading input from stdin...")
  msg = sys.stdin.readlines()

  resp = send(ip, port, "".join(msg))

  if resp.status == 200:
    print "OK!"
  else:
    print "Failed! %d %s" % (resp.status, resp.reason)

  print "Response: "
  print resp.read()
  print "=========================="

if __name__ == "__main__":
  main()
  
