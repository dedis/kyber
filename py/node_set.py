from logging import debug, info
import anon_node, random

class node_set():
	def __init__(self, n_nodes, socket_start, key_len):
		self.n_nodes = n_nodes
		self.socket_start = socket_start
		self.key_len = key_len
		self.round_id = random.randint(1, 10000)
		self.create_nodes()
	
	def create_nodes(self):
		for i in xrange(0, self.n_nodes):
			anon_node.anon_node(i, self.n_nodes,
					self.socket_start+i, self.key_len, self.round_id)
