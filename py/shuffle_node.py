import logging, random, sys
from time import sleep, time
from logging import debug, info, critical
import socket, cPickle, tempfile
import struct
from utils import Utilities
import M2Crypto.RSA
from anon_crypto import AnonCrypto
from anon_net import AnonNet

class shuffle_node():
	def __init__(self, id, key_len, round_id, n_nodes,
			my_addr, leader_addr, prev_addr, next_addr, msg_file):
		ip,port = my_addr

		self.start_time = time()
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

		self.msg_contents = Utilities.read_file_to_str(msg_file)

		info("Node started (id=%d, addr=%s:%d, key_len=%d, round_id=%d, n_nodes=%d)"
			% (id, ip, port, key_len, round_id, n_nodes))

		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)

		self.pub_keys = {}

		'''
		# Use this to test crypto functions
		self.generate_keys()

		if self.id > 0: sys.exit()
		m = '1' * 1000000
		c = AnonCrypto.encrypt_with_rsa(self.key1, m)
		self.debug("LENGTH: %d" % len(c))
		sys.exit()
		print self.decrypt_with_rsa(self.key1, c)
		sys.exit()
		'''

	def run_protocol(self):
		self.run_phase1()
		self.run_phase2()
		self.run_phase3()
		self.run_phase4()
		self.run_phase5()

		self.info("Finished in %g seconds" % (time() - self.start_time))

	def output_filenames(self):
		return self.write_anon_data_filenames()	

#
#
#

	def advance_phase(self):
		self.phase = self.phase + 1

	def datum_string(self):
		return self.msg_contents

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
			(all_msgs, addrs) = self.recv_from_n(self.n_nodes-1)
			
			# Get all node addrs via this msg
			self.addrs = self.unpickle_pub_keys(all_msgs)

			if not self.have_all_keys():
				raise RuntimeError, "Missing public keys"
			self.info('Leader has all public keys')

			pick_keys_str = self.phase1b_msg()
			self.broadcast_to_all_nodes(pick_keys_str)

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

			k1 = AnonCrypto.pub_key_from_str(s1)
			k2 = AnonCrypto.pub_key_from_str(s2)
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

			self.pub_keys[rem_id] = (
					AnonCrypto.pub_key_from_str(rem_key1),
					AnonCrypto.pub_key_from_str(rem_key2))
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
			newdict[i] = (
				AnonCrypto.pub_key_to_str(k1),
				 AnonCrypto.pub_key_to_str(k2))

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
			(self.data_in, addrs) = self.recv_from_n(self.n_nodes-1)
			self.info("Leader has all ciphertexts")

			# Leader must add own cipher to the set
			self.data_in.append(cPickle.dumps((self.round_id, self.cipher)))

		else:
			self.info("Sending cipher to leader")
			self.send_to_leader(cPickle.dumps((self.round_id, self.cipher)))
			self.info("Finished phase 2")


	def create_cipher_string(self):
		self.cipher_prime = self.datum_string()
		# Encrypt with all secondary keys from N ... 1
		
		for i in xrange(self.n_nodes - 1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher_prime = AnonCrypto.encrypt_with_rsa(k2, self.cipher_prime)

		self.cipher = self.cipher_prime

		# Encrypt with all primary keys from N ... 1
		for i in xrange(self.n_nodes-1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher = AnonCrypto.encrypt_with_rsa(k1, self.cipher)

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

		# Shuffle ciphertexts
		self.shuffle_and_decrypt()
		self.debug("Shuffled ciphers")
	
		outstr = cPickle.dumps(self.data_out)
		if self.am_last():
			self.debug("Sending ciphers to leader")
			self.send_to_leader(outstr)
		else:
			ip, port = self.next_addr
			AnonNet.send_to_addr(ip, port, outstr)
			self.debug("Sent set of ciphers")
		
		if self.am_leader():
			# Leader waits for ciphers from member N
			self.data_in = self.recv_cipher_set()

	def shuffle_and_decrypt(self):
		random.shuffle(self.data_in)
		self.data_out = []
		for ctuple in self.data_in:
			(rem_round, ctext) = cPickle.loads(ctuple)
			if rem_round != self.round_id:
				raise RuntimeError, "Mismatched round numbers (mine:%d, other:%d)" % (self.round_id, rem_round)

			new_ctext = AnonCrypto.decrypt_with_rsa(self.key1, ctext)	
			pickled = cPickle.dumps((self.round_id, new_ctext))
			self.data_out.append(pickled)

#
# PHASE 4
#
	def run_phase4(self):
		self.advance_phase()
		if self.am_leader():
			self.debug("Leader broadcasting ciphers to all nodes")
			self.broadcast_to_all_nodes(cPickle.dumps(self.data_in))
			self.debug("Cipher set len %d" % (len(self.data_in)))
			self.final_ciphers = self.data_in
		else:
			# Get C' ciphertexts from leader
			self.final_ciphers = self.recv_cipher_set()

		# self.final_ciphers holds an array of pickled (round_id, cipher_prime) tuples
		my_cipher_str = cPickle.dumps((self.round_id, self.cipher_prime))

		go = False
		if my_cipher_str in self.final_ciphers:
			self.info("Found my ciphertext in set")
			go = True
		else:
			self.critical("ABORT! My ciphertext is not in set!")
			go = False
			#raise RuntimeError, "Protocol violation: My ciphertext is missing!"

		hashval = AnonCrypto.hash_list(self.final_ciphers)
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
			self.send_to_leader(go_msg)
			(data, addrs) = self.recv_from_n(1)
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

		mykeystr = cPickle.dumps((
							self.id,
							self.round_id,
							AnonCrypto.priv_key_to_str(self.key2)))

		if self.am_leader():
			(data, addr) = self.recv_from_n(self.n_nodes - 1)
			data.append(mykeystr)
			self.debug("Key data...")
			self.broadcast_to_all_nodes(cPickle.dumps((data)))

		else:
			self.info('Sending key to leader')
			self.send_to_leader(mykeystr)
			(data, addr) = self.recv_from_n(1)
			self.info('Got key set from leader')
			data = cPickle.loads(data[0])

		self.decrypt_ciphers(data)
		self.info('Decrypted ciphertexts')
		
	def write_anon_data_filenames(self):
		filenames = []
		for i in xrange(0, len(self.anon_data)):
			handle, fname = tempfile.mkstemp()
			Utilities.write_str_to_file(fname, self.anon_data[i])
			filenames.append(fname)
		return filenames

	def decrypt_ciphers(self, keyset):
		priv_keys = {}
		for item in keyset:
			(r_id, r_roundid, r_keystr) = cPickle.loads(item)
			if r_roundid != self.round_id:
				raise RuntimeError, 'Mismatched round numbers'
			priv_keys[r_id] = AnonCrypto.priv_key_from_str(r_keystr)

		plaintexts = []
		for cipher in self.final_ciphers:
			(r_round, cipher_prime) = cPickle.loads(cipher)
			if r_round != self.round_id:
				raise RuntimeError, 'Mismatched round ids'
			for i in xrange(0, self.n_nodes):
				cipher_prime = AnonCrypto.decrypt_with_rsa(priv_keys[i], cipher_prime)
			plaintexts.append(cipher_prime)
		
		self.anon_data = plaintexts

#
# Network Utility Functions
#

	def recv_cipher_set(self):
		# data_in arrives as a singleton list of a pickled
		# list of ciphers.  we need to unpickle the first
		# element and use that as our array of ciphertexts
		(data, addrs) = self.recv_from_n(1)
		return cPickle.loads(data[0])

	def broadcast_to_all_nodes(self, msg):
		if not self.am_leader():
			raise RuntimeError, 'Only leader can broadcast'

		# Only leader can do this
		for i in xrange(0, self.n_nodes-1):
			ip, port = self.addrs[i]
			AnonNet.send_to_addr(ip, port, msg)

	def send_to_leader(self, msg):
		ip,port = self.leader_addr
		AnonNet.send_to_addr(ip, port, msg)

	def recv_from_n(self, n_backlog):
		return AnonNet.recv_from_n(self.ip, self.port, n_backlog)

#
# Utility Functions 
#


	def key_from_file(self, key_number):
		return Utilities.read_file_to_str(self.key_filename(key_number))

	def have_all_keys(self):
		return len(self.pub_keys) == self.n_nodes

	def generate_keys(self):	
		info("Generating keypair, please wait...")
		self.key1 = AnonCrypto.random_key(self.key_len)
		self.key2 = AnonCrypto.random_key(self.key_len)
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

	def debug(self, msg):
		debug(self.debug_str(msg))

	def critical(self, msg):
		critical(self.debug_str(msg))

	def info(self, msg):
		info(" " + self.debug_str(msg))

	def debug_str(self, msg):
		return "(NODE %d, PHZ %d - %s:%d) %s" % (self.id, self.phase, self.ip, self.port, msg)


