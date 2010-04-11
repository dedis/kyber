from logging import debug, info
import logging
import bulk_node, random
from subprocess import Popen
import sys

nodes = []
with open(sys.argv[1], 'r') as f:
	for line in f:
		parts = line.split()
		Popen(['ssh',"hnc4@%s" % parts[0], 'killall','python'])
		debug("Killall: %s" % parts[0])

