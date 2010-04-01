import logging
from logging import debug, info
import node_set
import sys


def __main__(argv):
	min_key_len = 1024

	if(len(argv) != 3):
		raise ValueError, "Usage: %s key_len node_file" % (argv[0])
	
	key_len = int(argv[1])
	filename = argv[2]

	if(key_len < min_key_len):
		raise ValueError, "Key length must be larger than ", min_key_len
	
	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)

	info("== Anonymous Protocol ==")
	info("Run as %s" % (argv[0]))
	info("key_len = %d" % (key_len))

	node_set.node_set(key_len, filename)

__main__(sys.argv)
