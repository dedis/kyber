import logging
from logging import debug, info
import node_set
import sys

def __main__(argv):
	min_nodes = 3
	min_socket_start = 5000
	min_key_len = 1024

	if(len(argv) < 3):
		raise ValueError, "Usage: %s n_nodes socket_start key_len" % (argv[0])
	
	n_nodes = int(argv[1])
	socket_start = int(argv[2])
	key_len = int(argv[3])

	if(n_nodes < min_nodes):
		raise ValueError, "Cannot run protocol with less than %d nodes" % (min_nodes)
	if(key_len < min_key_len):
		raise ValueError, "Key length must be larger than ", min_key_len
	if(socket_start < min_socket_start):
		raise ValueError, "Socket number must be larger than ", min_socket_start
	
	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)

	info("== Anonymous Protocol ==")
	info("Run as %s" % (argv[0]))
	info("n_nodes = %d" % (n_nodes))
	info("socket_start = %d" % (socket_start))
	info("key_len = %d" % (key_len))

	node_set.node_set(n_nodes, socket_start, key_len)



__main__(sys.argv)
