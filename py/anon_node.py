import logging, random
from time import sleep
from logging import debug, info, critical
import asyncore, socket, cPickle, tempfile
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

		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)

		self.pub_keys = {}

		self.run_phase1()

	def am_leader(self):
		return self.id == 0

#
# Protocol phases
#

	def run_phase1(self):
		self.public_keys = []
		self.generate_keys()

		if self.am_leader():
			debug('Leader starting phase 1')

			# set up server connection
			# and wait to get all keys
			server_sock = self.get_all_socket()
			sock_list = []
			while not self.have_all_keys():
				debug("Leader listening at %s:%d" % (self.ip, self.port))
				try:
					(rem_sock, (rem_ip, rem_port)) = server_sock.accept()
				except KeyboardInterrupt:
					server_sock.close()
					raise
				sock_list.append((rem_sock, (rem_ip, rem_port)))
				self.process_socket_phase1(rem_sock, rem_ip, rem_port)
			server_sock.close()
			info('Leader received all keys')
#self.rec_send_keys(sock_list)

		else:
			self.send_to_leader(self.phase1_msg())

			# Get all pub keys from leader

	def send_to_leader(self, msg):
		ip, port = self.leader_addr
		debug("Trying to connect to leader (%s, %d)" % (ip, port))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		for i in xrange(0, 10):
			try:
				s.connect((ip, port))
				break
			except socket.error, (errno, errstr):
				if errno == 61 or errno == 22: # Server not awake yet
					if i == 9:
						raise RuntimeError, "Cannot connect to server"
					debug("Node %d: Waiting for server..." % (self.id))
					sleep(random.randint(1,5))
				else: raise
			except KeyboardInterrupt:
				s.close()
				raise

		info("Connected to leader node")
		self.send_to_socket(s, msg)
		s.close()
		debug("Closed socket to leader node")


	def send_to_socket(self, socket, msg):
		# Snippet from http://www.amk.ca/python/howto/sockets/
		totalsent = 0
		while totalsent < len(msg):
			sent = socket.send(msg[totalsent:])
			debug("Node %d sent %d bytes" % (self.id, sent))
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent

	def process_socket_phase1(self, newsock, ip, port):
		info("Connected to %s:%d" % (ip, port)) 
		data = ""
		while True:
			newdat = newsock.recv(4096)
			if len(newdat) == 0: break
			data += newdat
		(rem_id, rem_round, rem_key1, rem_key2) = cPickle.loads(data)
		debug("Unpickled msg from node %d" % (rem_id))
		
		if rem_round != self.round_id:
			raise RuntimeError, "Mismatched round numbers! (mine: %d, other: %d)" % (
					self.round_id, rem_round)

		self.pub_keys[rem_id] = (
				self.pub_key_from_str(rem_key1),
				self.pub_key_from_str(rem_key2))
		return

	def get_all_socket(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(10.0)
		try:
			s.bind((self.ip, self.port))
		except socket.error, (errno, errstr):
			if errno == 48:
				critical('Leader cannot bind port')
			raise
		s.listen(self.n_nodes - 1)
		
		return s

	def phase1_msg(self):
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

	def pub_key_from_str(self, key_str):
		(handle, filename) = tempfile.mkstemp()
		with open(filename, 'w') as f:
			f.write(key_str)
		return M2Crypto.RSA.load_pub_key(filename)

	def key_from_file(self, key_number):
		str = ""
		with open(self.key_filename(key_number), 'r') as f:
			for line in f:
				str += line
		return str

	def have_all_keys(self):
		return len(self.pub_keys) == self.n_nodes

	def generate_keys(self):
		self.key1 = self.random_key()
		self.key2 = self.random_key()
		self.save_pub_key(self.key1, 1)
		self.save_pub_key(self.key2, 2)

		self.pub_keys[self.id] = (self.key1.pub(), self.key2.pub())

	def save_pub_key(self, rsa_key, key_number):
		rsa_key.save_pub_key(self.key_filename(key_number))

	def key_filename(self, key_number):
		return self.node_key_filename(self.id, key_number)

	def node_key_filename(self, node_id, key_number):
		return "/tmp/anon_node_%d_%d.pem" % (node_id, key_number)


	def random_key(self):
		info("Generating keypair, please wait...")
		return M2Crypto.RSA.gen_key(self.key_len, 65537)
		


