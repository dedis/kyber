from logging import debug, info
import logging
import bulk_node, random
from subprocess import Popen
import sys

class node_set():
	def __init__(self, argv):
		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)

		min_nodes = 3
		self.key_len = 1024
		self.round_id = random.randint(1, 10000)

		self.process_args(argv)
		
		if(len(self.nodes) < min_nodes):
			raise ValueError, "Cannot run protocol with less than %d nodes" % (min_nodes)

		self.processes = self.create_nodes()

	def process_args(self, argv):
		usagestr = "Usage: %s [-r|-l] [-s|-b] total_len [each|one] n_nodes address_filename" % argv[0]
		if len(argv) != 7: raise RuntimeError, usagestr

		if argv[1] == '-r':		self.remote = True
		elif argv[1] == '-l':	self.remote = False
		else: raise RuntimeError, usagestr

		if argv[2] == '-s':		self.bulk = False
		elif argv[2] == '-b':	self.bulk = True
		else: raise RuntimeError, usagestr

		if argv[4] == 'each':	self.shared = True
		elif argv[4] == 'one':	self.shared = False
		else: raise RuntimeError, usagestr
	
		self.nodes = self.parse_nodefile(int(argv[5]), argv[6])
		self.calculate_lengths(int(argv[3]), len(self.nodes))

	def create_nodes(self):
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
				args = ['ssh', "hnc4@%s" % my_ip, 'cd cs490;']
			args = args + ['python', progstr,
				str(i), str(self.key_len),
				str(self.round_id), str(len(self.nodes)),
				my_ip, str(my_port),
				leader_ip, str(leader_port),
				prev_ip, str(prev_port),
				next_ip, str(next_port),
				str(self.lengths[i])]
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

node_set(sys.argv)
