from __future__ import with_statement
from logging import debug, info
import logging
from .. import bulk_node, random
from subprocess import Popen
import sys

from settings import *

nodes = []
with open(sys.argv[1], 'r') as f:
	for line in f:
		parts = line.split()
		Popen(['ssh',"%s@%s%s" % (EMULAB_USERNAME, parts[0], EMULAB_SUFFIX), 'killall','python'])
		debug("Killall: %s" % parts[0])

