import logging, random, sys
from time import sleep
from logging import debug, info, critical
import asyncore, socket, cPickle, tempfile
import M2Crypto.RSA, struct, base64, M2Crypto.Rand

class anon_node():
	def __init__(self, id, key_len, round_id, n_nodes,
			my_addr, leader_addr, prev_addr, next_addr):
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
		self.prev_addr = prev_addr
		self.next_addr = next_addr
		self.phase = 0

		# A very unsecure initialization vector
		self.iv = 'al*73lf9)982'

		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)

		self.pub_keys = {}

		# Use this to test crypto functions
		'''
		self.generate_keys()
		print self.priv_key_to_str(self.key2)
	
		m = ''
		c = self.encrypt_with_rsa(self.key1, m)
		print self.decrypt_with_rsa(self.key1, c)
		sys.exit()
		'''
		self.initialize_sockets()

		try:
			self.run_phase1()
			self.run_phase2()
			self.run_phase3()
			self.run_phase4()
			self.run_phase5()
		except KeyboardInterrupt, SystemExit:
			self.close_sockets()
			raise

	def advance_phase(self):
		self.phase = self.phase + 1

	def datum_string(self):
		return "Secret anonymous message from node %d" % (self.id)

	def am_leader(self):
		return self.id == 0
	
	def am_last(self):
		return self.id == (self.n_nodes - 1)

#
# PHASE 1
#

	def run_phase1(self):
		self.advance_phase()
		self.public_keys = []
		self.generate_keys()

		if self.am_leader():
			self.debug('Leader starting phase 1')


			# We need to save addresses so that we can
			# broadcast to all nodes
			(all_msgs, addrs) = self.recv_from_all_nodes()
			
			# Get all node addrs via this msg
			self.addrs = self.unpickle_pub_keys(all_msgs)

			if not self.have_all_keys():
				raise RuntimeError, "Missing public keys"
			self.info('Leader has all public keys')

			pick_keys_str = self.phase1b_msg()
			self.send_to_all_nodes(pick_keys_str)

			self.info('Leader sent all public keys')

		else:
			self.send_to_leader(self.phase1_msg())
			junk = self.recv_from_leader()

			# Get all pub keys from leader
			(keys, addrs) = self.recv_from_leader()
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
# PHASE 2
#
	def run_phase2(self):
		self.advance_phase()
		self.info("Starting phase 2")

		self.create_cipher_string()
		if self.am_leader():
			self.info("Leader waiting for ciphers")
			(all_msgs, addrs) = self.recv_from_n(self.n_nodes-1)
			self.info("Leader has all ciphertexts")
			self.data_in = all_msgs

			# Leader must add own cipher to the set
			self.data_in.append(cPickle.dumps((self.round_id, self.cipher)))

		else:
			self.info("Sending cipher to leader")
			self.send_to_leader(cPickle.dumps((self.round_id, self.cipher)))
			self.info("Finished phase 2")


	def create_cipher_string(self):
		self.cipher_prime = self.datum_string()
		# Encrypt with all secondary keys from N ... 1
		for i in xrange(self.n_nodes-1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher_prime = self.encrypt_with_rsa(k2, self.cipher_prime)

		self.cipher = self.cipher_prime

		# Encrypt with all primary keys from N ... 1
		for i in xrange(self.n_nodes-1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher = self.encrypt_with_rsa(k1, self.cipher)

#
# PHASE 3
#
	
	def run_phase3(self):
		self.advance_phase()
		self.info("Starting phase 3")
	
		# Everyone (except leader) blocks waiting for msg from
		# previous node in the group
		if not self.am_leader():
			self.data_in = self.recv_cipher_set()
			self.debug("Got set of ciphers")
	
		self.shuffle_and_decrypt()
		self.debug("Shuffled ciphers")
		
		if self.am_last():
			self.debug("Sending ciphers to leader")
			self.send_to_leader(cPickle.dumps(self.data_out))
		else:
			ip, port = self.next_addr
			self.send_to_addr(ip, port,
					cPickle.dumps(self.data_out))
			self.debug("Sent set of ciphers")
		
		if self.am_leader():
			# Leader waits for ciphers from member N
			self.data_in = self.recv_cipher_set()

	def shuffle_and_decrypt(self):
		random.shuffle(self.data_in)
		self.data_out = []
		for ctuple in self.data_in:
			(rem_round, ctext) = cPickle.loads(ctuple)
			if int(rem_round) != self.round_id:
				raise RuntimeError, "Mismatched round numbers (mine:%d, other:%d)" % (self.round_id, rem_round)

			new_ctext = self.decrypt_with_rsa(self.key1, ctext)	
			pickled = cPickle.dumps((self.round_id, new_ctext))
			self.data_out.append(pickled)

#
# PHASE 4
#
	def run_phase4(self):
		self.advance_phase()
		if self.am_leader():
			self.debug("Leader broadcasting ciphers to all nodes")
			self.send_to_all_nodes(cPickle.dumps(self.data_in))
			self.debug("Cipher set len %d" % (len(self.data_in)))
		else:
			# Get C' ciphertexts from leader
			self.data_in = self.recv_cipher_set()
	
		my_cipher_str = cPickle.dumps((self.round_id, self.cipher_prime))

		go = False
		if my_cipher_str in self.data_in:
			self.info("Found my ciphertext in set")
			go = True
		else:
			self.critical("ABORT! My ciphertext is not in set!")
			go = False
			#raise RuntimeError, "Protocol violation: My ciphertext is missing!"

		hashval = self.hash_list(self.data_in)
		go_msg = cPickle.dumps((
					self.id,
					self.round_id,
					go,
					hashval))
		
		go_data = ''
		if self.am_leader():
			# Collect go msgs
			(data, addrs) = self.recv_from_n(self.n_nodes - 1)
			
			# Add leader's go message to set
			data.append(go_msg)
			go_data = cPickle.dumps((data))
			self.broadcast_to_all_nodes(go_data)

		else:
			# Send go msg to leader
			self.debug('Sending my GO message')
			self.send_to_leader(go_msg)
			self.debug('Waiting for collection of GO msgs')
			(data, addrs) = self.recv_from_n(1)
			self.debug('Got set of GO msgs')
			go_data = data[0]
		
		self.check_go_data(hashval, go_data)
		self.info("All nodes report GO")
		return

	def check_go_data(self, hashval, pickled_list):
		go_lst = cPickle.loads(pickled_list)
		for item in go_lst:
			(r_id, r_round, r_go, r_hash) = cPickle.loads(item)
			if r_round != self.round_id:
			 	raise RuntimeError, "Mismatched round numbers"
			if not r_go:
			 	raise RuntimeError, "Node %d reports failure!" % (r_id)
			if r_hash != hashval:
			 	raise RuntimeError, "Node %d produced bad hash!" % (r_id)
		return True

#
# PHASE 5
#

	def run_phase5(self):
		self.advance_phase()

		privkeys = []
		mykeystr = cPickle.dumps((
					self.id,
					self.round_id,
					self.priv_key_to_str(self.key2)))

		if self.am_leader():
			(data, addr) = self.recv_from_n(self.n_nodes - 1)
			data.append(mykeystr)
			self.broadcast_to_all_nodes(cPickle.dumps((data)))

		else:
			self.info('Sending key to leader')
			self.send_to_leader(mykeystr)
			(data, addr) = self.recv_from_n(1)
			self.info('Got key set from leader')
			data = cPickle.loads(data[0])
		
		self.decrypt_ciphers(data)
		self.info('Decrypted ciphertexts')
		for c in self.anon_data:
			self.info("MSG RECV'D: %s" % (c))

	def decrypt_ciphers(self, keyset):
		priv_keys = {}
		for item in keyset:
			(r_id, r_roundid, r_keystr) = cPickle.loads(item)
			if r_roundid != self.round_id:
				raise RuntimeError, 'Mismatched round numbers'
			self.debug(r_keystr)
			priv_keys[r_id] = self.priv_key_from_str(r_keystr)
	
		plaintexts = []
		for cipher in self.data_in:
			for i in xrange(self.n_nodes - 1, -1, -1):
				plaintexts.append(self.decrypt_with_rsa(priv_keys[i], cipher))
		
		self.anon_data = plaintexts


#
# Network Utility Functions
#

	def initialize_sockets(self):
		if self.am_leader():
			self.setup_leader_sockets()
			return

		p_ip, p_port = self.prev_addr
		n_ip, n_port = self.next_addr

		self.sock_prev = self.get_server_socket(1)
		self.info('Connected to prev node')
		
		self.socket_next = self.connect_to_addr(n_ip, n_port)
		self.info('Connected to next node')

		(l_ip, l_port) = self.leader_addr
		self.socket_leader = self.connect_to_addr(l_ip, l_port)

	def setup_leader_sockets(self):
		self.sockets = []
		data = []
		server_sock = self.get_server_socket(self.n_nodes - 1)
		for i in xrange(0, self.n_nodes):
			self.debug('Waiting for connections...')
			try:
				(r_sock, (r_ip, r_port)) = server_sock.accept()
			except KeyboardInterrupt:
				server_sock.close()
				raise
			self.sockets.append(r_sock)
		return server_sock

	def close_sockets(self):
		if self.am_leader():
			for s in self.sockets: s.close()
		else:
			self.socket.close()

	def connect_to_addr(self, ip, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		sleep(random.randint(1,5))
		for i in xrange(0, 20):
			try:
				s.connect((ip, port))
				break
			except socket.error, (errno, errstr):
				if errno == 61: # Server not awake yet
					if i == 19:
						raise RuntimeError, "Cannot connect to server"
					self.debug("Waiting for server...")
					sleep(random.randint(1,5))
				elif errno == 22:
					self.debug("Server (%s:%d) not listening yet..." % (ip, port))
					sleep(random.randint(1,5))
					if i == 19: raise
				else: raise
			except KeyboardInterrupt:
				s.close()
				raise
		return s

	def recv_cipher_set(self):
		# data_in arrives as a singleton list of a pickled
		# list of ciphers.  we need to unpickle the first
		# element and use that as our array of ciphertexts
		(data, addrs) = self.recv_from_n(1)
		return cPickle.loads(data[0])

	def send_to_all_nodes(self, msg):
		if not self.am_leader():
			raise RuntimeError, "Only leader can broadcast"
		for s in self.sockets:
			self.send_to_socket(s, msg)

	def recv_from_all_nodes(self):
		data = []
		if not self.am_leader():
			raise RuntimeError, "Only leader can recv from all nodes"
		for s in self.sockets:
		 	(ip, port) = s.getpeername()
		 	self.debug("Receiving from %s:%d" % (ip, port))
			data.append(self.recv_from_socket(s))
		return data

	def recv_from_leader(self):
		if self.am_leader():
			raise RuntimeError, 'Leader cannot send to self'
		return self.recv_from_socket(self.socket_leader)

	def send_to_leader(self, msg):
		if self.am_leader():
			raise RuntimeError, 'Leader cannot send to self'
		self.send_to_socket(self.socket_leader, msg)

	def junk_str(self):
		return ('JUNK' * 1024)

	def send_to_socket(self, sock, msg):
		msg += self.junk_str()
		# Prepend length of message in a long long int
		msg = struct.pack("!Q", len(msg)) + msg

		# Snippet from http://www.amk.ca/python/howto/sockets/
		self.debug('Starting to send')

		totalsent = 0
		while totalsent < len(msg):
			sent = sock.send(msg[totalsent:])
			self.debug("Sent %d bytes" % (sent))
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent
		self.debug("Message sent")
		return

	def recv_from_socket(self, sock):
		header_len = struct.calcsize("!Q")
		self.info("Reading %d header bytes from socket..." % (header_len))
		header = self.recv_n_bytes(sock, header_len)

		# Use header to determine data length
		# Second tuple is always empty for some reason
		(data_len,) = struct.unpack("!Q", header)
		self.info("Reading %d data bytes from socket" % (data_len))
		data = self.recv_n_bytes(sock, data_len)
		return data[:len(data) - len(self.junk_str())]
	
	def recv_n_bytes(self, sock, n_bytes):
		data = ""
		bytes_left = n_bytes
		while True:
			try:
				newdata = sock.recv(bytes_left)
				self.debug("Got %d bytes" % (len(newdata)))
				data = data + newdata
			except socket.error, (errno, errstr):
				# Error 35 means nothing has been sent yet
				if errno == 35: continue
				else: raise
			if len(data) == n_bytes:
				break
			elif len(data) == 0:
			 	raise RuntimeError, "Remote peer cut the connection"
			else:
				bytes_left = bytes_left - len(newdata)
		return data

	def get_server_socket(self, n_backlog):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.IPPROTO_TCP, socket.SO_KEEPALIVE, 1)
		s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		s.setblocking(1)
		s.settimeout(30.0 * self.n_nodes)
		try:
			s.bind((self.ip, self.port))
		except socket.error, (errno, errstr):
			if errno == 48: self.critical('Cannot bind server port')
			raise
		s.listen(n_backlog)
		self.debug("Server listening at %s:%d" % (self.ip, self.port))
		
		return s


#
# Encryption
#

	def encrypt_with_rsa(self, pubkey, msg):
		session_key = M2Crypto.Rand.rand_bytes(32)
		
		# AES must be padded to make 16-byte blocks
		# Since we prepend msg with # of padding bits
		# we actually need one less padding bit
		n_padding = ((16 - (len(msg) % 16)) - 1) % 16
		padding = '\0' * n_padding

		pad_struct = struct.pack('!B', n_padding)

		encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, self.iv, M2Crypto.encrypt)

		# Output is tuple (E_rsa(session_key), E_aes(session_key, msg))
		return cPickle.dumps((
					pubkey.public_encrypt(session_key, M2Crypto.RSA.pkcs1_oaep_padding),
					encrypt.update(pad_struct + msg + padding)))

	def decrypt_with_rsa(self, privkey, ciphertuple):
		session_cipher, ciphertext = cPickle.loads(ciphertuple) 
		
		# Get session key using RSA decryption
		session_key = privkey.private_decrypt(session_cipher, 
				M2Crypto.RSA.pkcs1_oaep_padding)
		
		# Use session key to recover string
		dummy_block =  ' ' * 8
		decrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, self.iv, M2Crypto.decrypt)

		outstr = decrypt.update(ciphertext) + decrypt.update(dummy_block)
		pad_data = outstr[0]
		outstr = outstr[1:]

		# Get num of bytes added at end
		n_padding = struct.unpack('!B', pad_data)
		
		# Second element of tuple is always empty for some reason
		n_padding = n_padding[0]
		outstr = outstr[:(len(outstr) - n_padding)]

		return outstr


#
# Key and file IO
#

	def hash_list(self, lst):
		lstr = cPickle.dumps((lst))
		return self.hash(lstr)

	def hash(self, msg):
		h = M2Crypto.EVP.MessageDigest('sha1')
		h.update(msg)
		return h.final()

	def priv_key_to_str(self, privkey):
		(handle, filename) = tempfile.mkstemp()
		privkey.save_key(filename, callback = lambda x: '')
		return self.key_from_filename(filename)		

	def priv_key_from_str(self, key_str):
		(handle, filename) = tempfile.mkstemp()
		f = open(filename, 'w')
		f.write(key_str)
		f.close()

		return M2Crypto.RSA.load_key(filename, callback = lambda x: '')

	def pub_key_to_str(self, pubkey):
		(handle, filename) = tempfile.mkstemp()
		pubkey.save_key(filename)
		return self.key_from_filename(filename)

	def pub_key_from_str(self, key_str):
		(handle, filename) = tempfile.mkstemp()
		f = open(filename, 'w')
		f.write(key_str)
		f.close()

		return M2Crypto.RSA.load_pub_key(filename)

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

	def critical(self, msg):
		critical(self.debug_str(msg))

	def info(self, msg):
		info(" " + self.debug_str(msg))

	def debug_str(self, msg):
		return "(NODE %d, PHZ %d - %s:%d) %s" % (self.id, self.phase, self.ip, self.port, msg)


