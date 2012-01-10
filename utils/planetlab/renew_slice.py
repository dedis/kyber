#!/usr/bin/python
# Sets the maximum lifetime for a slice or slices
import getpass, sys, time, xmlrpclib
 
api_server = xmlrpclib.ServerProxy('https://www.planet-lab.org/PLCAPI/', allow_none=True)
 
# Create an empty dictionary (XML-RPC struct)
auth = {}
 
# Specify password authentication
auth['AuthMethod'] = 'password'
 
print "Username: "
username = raw_input(">")
password = getpass.getpass()
# Username and password
auth['Username'] = username
auth['AuthString'] = password
 
authorized = False
try:
# Checks to see if we are authorized
  authorized = api_server.AuthCheck(auth)
except:
  sys.exit()
if authorized:
  print 'We are authorized!'
 
print "Enter Slice Name(s) - separated by commas: "
slices = raw_input(">")
slices = slices.split(",")

tse = int(time.time()) + 59*60*24*7*8
for slice in slices:
  slice = slice.strip()
  result = api_server.UpdateSlice(auth, slice, {"expires": tse})
  if result == 1:
    print slice + " Successful"
  else:
    print slice + " Failure"
