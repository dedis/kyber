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
			self.debug('Leader starting phase 1')

			(all_msgs, addrs) = self.recv_from_n(self.n_nodes-1)
			addrs = self.unpickle_pub_keys(all_msgs)

			if not self.have_all_keys():
				raise RuntimeError, "Missing public keys"
			self.info('Leader has all public keys')

			pick_keys_str = self.phase1b_msg()
			for i in xrange(0, self.n_nodes-1):
				ip, port = addrs[i]
				self.send_to_addr(ip, port, pick_keys_str)
			self.info('Leader sent all public keys')

		else:
			self.send_to_leader(self.phase1_msg())
		
			# Get all pub keys from leader
			(keys, addrs) = self.recv_from_n(1)
			self.unpickle_keyset(keys[0])

			self.info('Got keys from leader!')

	def unpickle_keyset(self, keys):
		(rem_round_id, keydict) = cPickle.loads(keys)

		if rem_round_id != self.round_id:
			raise RuntimeError, "Mismatched round ids"

		for i in keydict:
			s1,s2 = keydict[i]

			k1 = self.pub_key_from_str(s1)
			k2 = self.pub_key_from_str(s2)
			k1.check_key()
			k2.check_key()
			self.pub_keys[i] = (k1, k2)

		self.info('Unpickled public keys')

	def unpickle_pub_keys(self, msgs):
		addrs = []
		for data in msgs:
			(rem_id, rem_round, rem_ip, rem_port,
			 rem_key1, rem_key2) = cPickle.loads(data)
			self.debug("Unpickled msg from node %d" % (rem_id))
			
			if rem_round != self.round_id:
				raise RuntimeError, "Mismatched round numbers! (mine: %d, other: %d)" % (
						self.round_id, rem_round)

			self.pub_keys[rem_id] = (self.pub_key_from_str(rem_key1),
				self.pub_key_from_str(rem_key2))
			addrs.append((rem_ip, rem_port))
		return addrs

	def recv_from_n(self, n_backlog):
		self.debug('Setting up server socket')
		# set up server connection 
		addrs = []
		server_sock = self.get_server_socket(n_backlog)
		data = []
		for i in xrange(0, n_backlog):
			self.debug("Listening...")
			try:
				(rem_sock, (rem_ip, rem_port)) = server_sock.accept()
				addrs.append((rem_ip, rem_port))
			except KeyboardInterrupt:
				server_sock.close()
				raise
			data.append(self.recv_from_sock(rem_sock, rem_ip, rem_port))
		server_sock.close()
		return (data, addrs)

	def send_to_leader(self, msg):
		ip,port = self.leader_addr
		self.send_to_addr(ip, port, msg)

	def send_to_addr(self, ip, port, msg):
		self.debug("Trying to connect to (%s, %d)" % (ip, port))
		sleep(random.randint(1,5))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		for i in xrange(0, 10):
			try:
				s.connect((ip, port))
				break
			except socket.error, (errno, errstr):
				if errno == 61 or errno == 22: # Server not awake yet
					if i == 9:
						raise RuntimeError, "Cannot connect to server"
					self.debug("Waiting for server...")
					sleep(random.randint(1,5))
				else: raise
			except KeyboardInterrupt:
				s.close()
				raise

		self.info("Connected to node")
		self.send_to_socket(s, msg)
		s.close()
		self.debug("Closed socket to server")


	def send_to_socket(self, socket, msg):
		# Snippet from http://www.amk.ca/python/howto/sockets/
		totalsent = 0
		while totalsent < len(msg):
			sent = socket.send(msg[totalsent:])
			self.debug("Sent %d bytes" % (sent))
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent

	def recv_from_sock(self, newsock, ip, port):
		self.info("Reading from %s:%d" % (ip, port)) 
		data = ""
		while True:
			try:
				newdat = newsock.recv(4096)
			except socket.error, (errno, errstr):
				if errno == 35: continue
				else: raise
			if len(newdat) == 0: break
			data += newdat
		return data


	def get_server_socket(self, n_backlog):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setblocking(1)
		s.settimeout(5.0 * self.n_nodes)
		try:
			s.bind((self.ip, self.port))
		except socket.error, (errno, errstr):
			if errno == 48:
				critical('Leader cannot bind port')
			raise
		s.listen(n_backlog)
		self.debug("Socket listening at %s:%d" % (self.ip, self.port))
		
		return s

	def phase1_msg(self):
		return cPickle.dumps(
				(self.id,
					self.round_id, 
					self.ip,
					self.port,
					self.key_from_file(1),
					self.key_from_file(2)))
	
	def phase1b_msg(self):
		newdict = {}
		for i in xrange(0, self.n_nodes):
			k1,k2 = self.pub_keys[i]
			newdict[i] = (self.pub_key_to_str(k1), self.pub_key_to_str(k2))

		return cPickle.dumps((self.round_id, newdict))
#
# Network stuff
#

	def set_up_connections(self):
		# Server for i-1, client to i+1
		pass
		

#
# Key and file IO
#

	def pub_key_to_str(self, pubkey):
		(handle, filename) = tempfile.mkstemp()
		pubkey.save_key(filename)
		return self.key_from_filename(filename)


	def pub_key_from_str(self, key_str):
		(handle, filename) = tempfile.mkstemp()
		f = open(filename, 'w')
		f.write(key_str)
		f.close()

		key = M2Crypto.RSA.load_pub_key(filename)
		return key

	def key_from_file(self, key_number):
		return self.key_from_filename(self.key_filename(key_number))
	
	def key_from_filename(self, filename):
		str = ""
		with open(filename, 'r') as f:
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

		self.pub_keys[self.id] = (
				M2Crypto.RSA.load_pub_key(self.key_filename(1)),
				M2Crypto.RSA.load_pub_key(self.key_filename(2))) 
	
	def save_pub_key(self, rsa_key, key_number):
		rsa_key.save_pub_key(self.key_filename(key_number))

	def key_filename(self, key_number):
		return self.node_key_filename(self.id, key_number)

	def node_key_filename(self, node_id, key_number):
		return "/tmp/anon_node_%d_%d.pem" % (node_id, key_number)

	def random_key(self):
		info("Generating keypair, please wait...")
		return M2Crypto.RSA.gen_key(self.key_len, 65537)

	def debug(self, msg):
		debug(self.debug_str(msg))

	def info(self, msg):
		info(" " + self.debug_str(msg))

	def debug_str(self, msg):
		return "(NODE %d - %s:%d) %s" % (self.id, self.ip, self.port, msg)


