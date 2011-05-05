"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: main.py
Description: Test driver for anon protocol.  Designed to be
used as a command-line tool.
Author: Henry Corrigan-Gibbs
"""

from __future__ import with_statement
from subprocess import Popen
import sys
import logging
from logging import debug, info

import bulk_node, random
from settings import *

class node_set():
	def __init__(self, argv):
		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)

		self.user = ZOO_USERNAME
		self.dir = ZOO_SUBDIR
		self.node_append = ''
		self.bad_nodes=[]
		self.bad_mode = 0
		min_nodes = 3
		self.key_len = 1024
		self.round_id = random.randint(1, 10000) 
		self.process_args(argv)
		
		if(len(self.nodes) < min_nodes):
			raise ValueError, "Cannot run protocol with less than %d nodes" % (min_nodes)

		self.processes = self.create_nodes()

	def process_args(self, argv):
		helpmsg = \
		"""
		-z -- Zoo mode.  	(YALE INTERNAL USE ONLY)
							Use SSH to log in to the remote host
							and execute the node program there.
		-l -- Local mode.   Run the node program on the local host.
		-e -- Emulab mode.  Run with SSH and change to the right
							directory for emulab tests.

		-s -- Shuffle only. Exchange data using the shuffle protocol
							only.
		-b -- Bulk/shuffle. Exchange data using shuffle+bulk protocol.
							This is what you want to use for long messages.
		
		total_len -- The total amount of data to be exchanged (in bytes).

		each -- Equal data mode.  The total_len bytes are distributed 
							among all nodes equally.  
		one  -- One big message mode.  Each node sends 128 bytes of data
							except one node, who sends a message of size
							(total_len - 128 * (n_nodes - 1)) bytes.

		n_nodes -- Number of nodes to run the protocol on.  The actual
							number of nodes is the minimum of n_nodes and
							the number of nodes listed in your address file.

		address_filename -- Filename containing node addresses.  This is a
							plain text file with one line per node.  Each
							line has an IPv4 address/hostname and a port
							number separated by whitespace.
		bad_node_number --  The id of the bad node
		bad_node_mode   --  0: Duplicate or faulty ciphertext in phase 3, or Go-false in phase 4
                            1: Fake "Go=false" in phase 4
                            2: Incorrect Hash(B) in phase 4
                            3: Bad secondary key in phase 5(a)
		"""
		usagestr = "Usage: %s [-z|-l|-e] [-s|-b] total_len [each|one] bad_node_id [0|1|2|3] " % argv[0] + \
					"n_nodes address_filename bad_node_number bad_node_mode\n\n %s " % helpmsg

		if len(argv) < 7 or len(argv)>9: raise RuntimeError, usagestr

		if argv[1] == '-z':		self.remote = True
		elif argv[1] == '-l':	self.remote = False
		elif argv[1] == '-e':
			self.remote = True
			self.dir = EMULAB_ROOT_DIR
			self.user = EMULAB_USERNAME
			self.node_append = EMULAB_SUFFIX
		else: raise RuntimeError, usagestr

		if argv[2] == '-s':		self.bulk = False
		elif argv[2] == '-b':	self.bulk = True
		else: raise RuntimeError, usagestr

		if argv[4] == 'each':	self.shared = True
		elif argv[4] == 'one':	self.shared = False
		else: raise RuntimeError, usagestr
	
		self.n_nodes = int(argv[5])
		self.nodes = self.parse_nodefile(int(argv[5]), argv[6])
		self.calculate_lengths(int(argv[3]), len(self.nodes))
		
		if len(argv)>7:
			self.bad_nodes.append(int(argv[7]))
		if len(argv)>8:
			self.bad_mode = int(argv[8])

	def create_nodes(self):
		if len(self.nodes) < self.n_nodes:
			raise RuntimeError, "Trying to start %d nodes but only %d nodes in address file" % (self.n_nodes, len(self.nodes))

		processes = []
		leader_ip, leader_port = self.nodes[0]

		if self.bulk: progstr 	= 'run_bulk.py'
		else: progstr			= 'run_shuffle.py'
		
		for i in xrange(0, len(self.nodes)):
			my_ip, my_port = self.nodes[i]
			prev_ip, prev_port = self.nodes[(i-1)%len(self.nodes)] 
			next_ip, next_port = self.nodes[(i+1)%len(self.nodes)] 
			args = []

			# If connecting remotely, use SSH
			if self.remote:
				args = ['ssh', '-q', '-oStrictHostKeyChecking no',
				"%s@%s%s" % (self.user,my_ip,self.node_append), "cd %s;" % self.dir]
			if (not i in self.bad_nodes):			    
				args = args + ['time','python', progstr,
				str(i), str(self.key_len),
				str(self.round_id), str(len(self.nodes)),
				my_ip, str(my_port),
				leader_ip, str(leader_port),
				prev_ip, str(prev_port),
				next_ip, str(next_port),
				str(self.lengths[i])]
			else:
			    args = args + ['time','python', 'run_bad_shuffle.py',
				str(i), str(self.key_len),
				str(self.round_id), str(len(self.nodes)),
				my_ip, str(my_port),
				leader_ip, str(leader_port),
				prev_ip, str(prev_port),
				next_ip, str(next_port),
				str(self.lengths[i])]
			if not self.bulk:
				args = args + [str(max(self.lengths))]
			if i in self.bad_nodes:
				args = args + [str(self.bad_mode)]
			debug(args)
			processes.append(Popen(args))
		return processes

	def calculate_lengths(self, total_len, n_nodes):
		self.lengths = []
		if self.shared:
			for i in xrange(0, n_nodes):
				self.lengths.append(total_len / n_nodes)
		else:
			thenode = random.randint(0, n_nodes-1)
			for i in xrange(0, n_nodes):
				if i == thenode: mylen = max(total_len - (128 * (n_nodes-1)), 128)
				else: mylen = 128
				self.lengths.append(mylen)
		debug(self.lengths)

	def parse_nodefile(self, n_nodes, filename):
		nodes = []
		with open(filename, 'r') as f:
			for line in f:
				if len(nodes) >= n_nodes: break
				parts = line.split()
				if len(parts) < 2:
					raise SyntaxError, "Cannot parse node file"
				nodes.append((parts[0],int(parts[1])))
		return nodes

if __name__ == '__main__':
	node_set(sys.argv)
