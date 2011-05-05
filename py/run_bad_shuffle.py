"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: run_shuffle.py
Author: Henry Corrigan-Gibbs
"""
import logging
from logging import debug, info
import shuffle_node
import sys
from shutil import copyfile
from anon_crypto import AnonCrypto
import cProfile

def __main__(argv):
	min_key_len = 1024

	if(len(argv) != 16):
		raise ValueError, "Usage: %s id key_len round_id n_nodes my_ip my_port leader_ip leader_port dnstr_ip dnstr_port upstr_ip upstr_port msg_len max_len mode" % (argv[0])

	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)

	id = int(argv[1])
	key_len = int(argv[2])
	round_id = int(argv[3])
	n_nodes = int(argv[4])
	my_addr = (argv[5], int(argv[6]))
	leader_addr = (argv[7], int(argv[8]))
	up_addr = (argv[9], int(argv[10]))
	dn_addr = (argv[11], int(argv[12]))
	msg_len = int(argv[13])
	max_len = int(argv[14])
	mode = int (argv[15])
	
	msg_file = AnonCrypto.random_file(msg_len)
	node = shuffle_node.shuffle_node(id, key_len, round_id, n_nodes,
			my_addr, leader_addr, up_addr, dn_addr, msg_file, max_len)
	
#cProfile.runctx('node.run_protocol()', {}, {'node': node})
	node.run_bad_protocol(mode)
	fnames = node.output_filenames()
	print "--------------------------------------------------------------------"
#	for i in xrange(0, len(fnames)):
#		copyfile(fnames[i], "data/node%04d-%04d.out" % (id, i))

	return

__main__(sys.argv)
