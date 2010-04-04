from logging import debug, info
import anon_node, random
from subprocess import Popen

class node_set():
	def __init__(self, key_len, filename):
		min_nodes = 3

		self.key_len = key_len
		self.round_id = random.randint(1, 10000)

		self.nodes = self.parse_nodefile(filename)

		if(len(self.nodes) < min_nodes):
			raise ValueError, "Cannot run protocol with less than %d nodes" % (min_nodes)
		
		self.processes = self.create_nodes()

	def create_nodes(self):
		processes = []
		leader_ip, leader_port = self.nodes[0]
		for i in xrange(0, len(self.nodes)):
			my_ip, my_port = self.nodes[i]
			prev_ip, prev_port = self.nodes[(i-1)%len(self.nodes)] 
			next_ip, next_port = self.nodes[(i+1)%len(self.nodes)] 
			args = ['python', 'run_node.py',
				str(i), str(self.key_len),
				str(self.round_id), str(len(self.nodes)),
				my_ip, str(my_port),
				leader_ip, str(leader_port),
				prev_ip, str(prev_port),
				next_ip, str(next_port),
				"data/node%04i.msg" % i]
			debug(args)
			processes.append(Popen(args))
		return processes

	def parse_nodefile(self, filename):
		nodes = []
		with open(filename, 'r') as f:
			for line in f:
				parts = line.split()
				if len(parts) < 2:
					raise SyntaxError, "Cannot parse node file"
				nodes.append((parts[0],int(parts[1])))
		return nodes

