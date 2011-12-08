#!/usr/bin/python

import sys
import httplib

def try_service(server, port, method, path):
  print "{:>4}: {:<15} | ".format(method, path),
  conn = httplib.HTTPConnection(server, port)

  print "Requesting, ",
  conn.request(method, path)

  res = conn.getresponse()

  if res.status == 200:
    print "OK"
    return True
  else:
    print "Failed!"
    print "\t[%s] %s" % (res.status, res.reason)

def main():
  if len(sys.argv) != 3:
    sys.stderr.write("Usage: %s server port\n" % sys.argv[0])
    return

  server = sys.argv[1]
  port = int(sys.argv[2])

  services = [
    ("GET", "/session/id"),
    ("GET", "/round/id"),
    ("GET", "/session/messages/all"),
  ] 

  count = 0
  print "=== Using server %s:%d ===" % (server, port)
  for s in services:
    if try_service(server, port, s[0], s[1]):
      count += 1

  print "=========================="
  print "%d OK, %d failed" % (count, len(services) - count)

if __name__ == "__main__":
  main()
  
