import logging, random
from logging import debug, info
import asyncore, socket, cPickle
import M2Crypto.RSA

class anon_node():
	def __init__(self, id, total_nodes, socket_n, key_len, round_id):
		info("Node started (id=%d, total_nodes=%d, socket_n=%d, key_len=%d, round_id=%d)"
			% (id, total_nodes, socket_n, key_len, round_id))

		self.id = id
		self.downstream = (id - 1) % total_nodes
		self.upstream = (id + 1) % total_nodes

		self.total_nodes = total_nodes
		self.socket_n = socket_n
		self.key_len = key_len
		self.round_id = round_id 

#
# Protocol phases
#

	def run_phase1(self):
		self.generate_keys()

	def phase1_msg(self):
		return "Test from #%d" % (id)
		return cPickle.dumps(
				(self.id,
					self.round_id, 
					self.key_from_file(1),
					self.key_from_file(2)))


#
# Network stuff
#

	def set_up_connections(self):
		# Server for i-1, client to i+1
		
		

	def port_for_node(self, node_id):
		return self.socket_n + node_id

#
# Key and file IO
#
	def key_from_file(self, key_number):
		str = ""
		f = open(self.key_filename(key_number), 'r')
		for line in f:
			str += line
		return str

	def generate_keys(self):
		self.key1 = self.random_key()
		self.key2 = self.random_key()
		self.save_pub_key(self.key1, 1)
		self.save_pub_key(self.key2, 2)

	def save_pub_key(self, rsa_key, key_number):
		rsa_key.save_pub_key(self.key_filename(key_number))

	def key_filename(self, key_number):
		return "/tmp/anon_node_%d_%d.pem" % (self.id, key_number)
	
	def random_key(self):
		info("Generating keypair, please wait...")
		return M2Crypto.RSA.gen_key(self.key_len, 65537)
		


