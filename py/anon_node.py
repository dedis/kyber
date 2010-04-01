import logging, random
from time import sleep
from logging import debug, info
import asyncore, socket, cPickle
import M2Crypto.RSA

class anon_node():
	def __init__(self, id, key_len, round_id, n_nodes,
			my_addr, leader_addr, upstream_addr, downstream_addr):
		ip,port = my_addr
		info("Node started (id=%d, addr=%s:%d, key_len=%d, round_id=%d, n_nodes=%d)"
			% (id, ip, port, key_len, round_id, n_nodes))

		self.id = id
		self.key_len = key_len
		self.n_nodes = n_nodes
		self.ip = ip
		self.port = int(port)
		self.round_id = round_id
		self.leader_addr = leader_addr
		self.upstream_addr = upstream_addr
		self.downstream_addr = downstream_addr

	def am_leader(self):
		return id == 0

#
# Protocol phases
#

	def run_phase1(self):
		self.public_keys = []
		self.generate_keys()

		if self.am_leader():
			# set up server connection
			# and wait to get all keys
			socket = self.get_all_socket()
			all_socks = []
			for i in xrange(0, self.n_nodes-1):
				conn, addr = socket.accept()
				all_socks.append((conn, addr))
			socket.close()
		
			self.rec_send_keys(all_socks)
		else:
			--try to connect to leader
			  and write my key
			--try to read from leader
			  and get all keys
	
	def rec_send_keys(self, all_socks):
		data = {}
		for i in xrange(0, len(all_socks)):
			data[i] = ""


	def get_all_socket(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((self.ip, self.port))
		s.listen(self.n_nodes - 1)

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
		pass
		

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
		


