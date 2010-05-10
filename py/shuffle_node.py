"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: shuffle_node.py
Description: Implementation of the shuffle component
of the anon protocol.
Author: Henry Corrigan-Gibbs
"""

import logging, random, sys
from time import sleep, time
from logging import debug, info, critical
import socket, tempfile
import marshal
import struct
import resource

import M2Crypto.RSA

from anon_crypto import AnonCrypto
from utils import Utilities
from anon_net import AnonNet

class shuffle_node():
	def __init__(self, id, key_len, round_id, n_nodes,
			my_addr, leader_addr, prev_addr, next_addr, msg_file, max_len, sockets = None):
		ip,port = my_addr

		self.start_time = time()
		self.sockets = sockets
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
		self.cleanup = False
		self.max_len = max_len
		self.rusage_start = (
				resource.getrusage(resource.RUSAGE_SELF).ru_utime,
				resource.getrusage(resource.RUSAGE_SELF).ru_stime)

		self.package_msg(msg_file)
		info("Node started (id=%d, addr=%s:%d, key_len=%d, round_id=%d, n_nodes=%d)"
			% (id, ip, port, key_len, round_id, n_nodes))

		logger = logging.getLogger()
		h = logging.FileHandler("logs/node%04d.final" % self.id)
		h.setLevel(logging.CRITICAL)
		logger.addHandler(h)
		logger.setLevel(logging.DEBUG)

		self.pub_keys = {}

		'''
		# Use this to test crypto functions
		self.generate_keys()

		if self.id > 0: sys.exit()
		m = '1' * 1000000
		signed = AnonCrypto.sign(self.key1, m)
		output = AnonCrypto.verify(self.key1, signed)
		self.debug(output)
		sys.exit()
		'''

	def package_msg(self, msg_file):
		"""
		Pad msg so that is max_len bytes long.  If nodes' messages
		are different lengths, the anonymity of the protocol is broken.
		"""
		msg = Utilities.read_file_to_str(msg_file)

		self.msg_contents = marshal.dumps(
				(len(msg), 
				msg + ('X' * (self.max_len - len(msg)))))

	def unpackage_msg(self, msg_str):
		(mlen, padded_msg) = marshal.loads(msg_str)
		self.debug("Got msg len %d, max_len %d" % (len(padded_msg), self.max_len))
		if len(padded_msg) != self.max_len:
		 	raise RuntimeError, 'Message strings are of differing lengths'
		return padded_msg[:mlen]

	def run_protocol(self):

		if self.sockets == None:
			""" Need to set up sockets """
			self.setup_sockets()
		elif len(self.sockets) == 1:
			""" This is a non-leader node """
			self.leader_socket = self.sockets[0]
			self.sockets = None

		try:
			self.run_phase1()
			self.run_phase2()
			self.run_phase3()
			self.run_phase4()
			self.run_phase5()
		except:
			self.cleanup_sockets()
			raise
		self.cleanup_sockets()

		self.info("Finished in %g seconds" % (time() - self.start_time))
		self.critical("SUCCESSROUND:SHUFFLE, RID:%d, NNOD:%d, WALLTIME:%g, USR:%g, SYS:%g\n\t%s" % \
				(self.round_id,
				 self.n_nodes, 
				 time() - self.start_time, 
				 resource.getrusage(resource.RUSAGE_SELF).ru_utime - self.rusage_start[0],
				 resource.getrusage(resource.RUSAGE_SELF).ru_stime - self.rusage_start[1],
				 self.size_string()))

	def size_string(self):
		c = ''
		for d in self.anon_data:
			c = c + ",%d" % len(d)
		return c

	def output_filenames(self):
		return self.write_anon_data_filenames()	

	def advance_phase(self):
		self.phase = self.phase + 1

	def datum_string(self):
		return self.msg_contents

	def am_leader(self):
		return self.id == 0
	
	def am_last(self):
		return self.id == (self.n_nodes - 1)

	"""
	PHASE 1

	Key exchange.  This is totally unsecure.  In a real 
	implementation every node would have the primary
	public key of every other node before the protocol begins.
	"""

	def run_phase1(self):
		self.advance_phase()
		self.public_keys = []
		self.generate_keys()

		if self.am_leader():
			self.debug('Leader starting phase 1')

			all_msgs = self.recv_from_all(False)
			
			""" Get all node addrs via this msg. """
			next_msg, self.addrs = self.unpickle_pub_keys(all_msgs)

			if not self.have_all_keys():
				raise RuntimeError, "Missing public keys"
			self.info('Leader has all public keys')

			self.broadcast_to_all_nodes(next_msg, False)

			self.info('Leader sent all public keys')

		else:
			self.send_to_leader(self.phase1_msg(), False)
		
			""" Get all pub keys from leader. """
			self.unpickle_keyset(self.recv_from_leader(False))

			self.info('Got keys from leader!')

	def unpickle_keyset(self, keys):
		""" Non-leader nodes use this to decode leader's key msg """
		(rem_round_id, keydict) = marshal.loads(keys)

		if rem_round_id != self.round_id:
			raise RuntimeError, "Mismatched round ids"

		for i in keydict:
			s1,s2 = keydict[i]

			k1 = AnonCrypto.pub_key_from_str(s1)
			k1.check_key()
			self.pub_keys[i] = (k1, k1)
			
			k2 = AnonCrypto.pub_key_from_str(AnonCrypto.verify(self.pub_keys, s2))
			k2.check_key()
			self.pub_keys[i] = (k1, k2)

		self.info('Unpickled public keys')

	def unpickle_pub_keys(self, msgs):
		""" Leader uses this method to unpack keys from other nodes """
		addrs = []
		key_dict = {}
		key_dict[self.id] = (
				self.key_from_file(1),
				AnonCrypto.sign(self.id, self.key1, self.key_from_file(2)))

		for data in msgs:
			(rem_id, rem_round, rem_ip, rem_port,
			 rem_key1, rem_key2) = marshal.loads(data)
			self.debug("Unpickled msg from node %d" % (rem_id))
			
			if rem_round != self.round_id:
				raise RuntimeError, "Mismatched round numbers! (mine: %d, other: %d)" % (
						self.round_id, rem_round)

			k1 = AnonCrypto.pub_key_from_str(rem_key1)
			self.pub_keys[rem_id] = (k1, k1)
			k2 = AnonCrypto.pub_key_from_str(AnonCrypto.verify(self.pub_keys, rem_key2))
			self.pub_keys[rem_id] = (k1, k2)
			addrs.append((rem_ip, rem_port))
			key_dict[rem_id] = (rem_key1, rem_key2)
		
		return (marshal.dumps((self.round_id, key_dict)), addrs)

	def phase1_msg(self):
		""" Message that non-leader nodes send to the leader. """
		return marshal.dumps(
				(self.id,
					self.round_id, 
					self.ip,
					self.port,
					self.key_from_file(1),
					AnonCrypto.sign(self.id, self.key1, self.key_from_file(2))))
	
		return marshal.dumps((self.round_id, newdict))

	"""
	PHASE 2

	Data submission.
	"""
	def run_phase2(self):
		self.advance_phase()
		self.info("Starting phase 2")

		self.create_cipher_string()
		if self.am_leader():
			self.info("Leader waiting for ciphers")
			self.data_in = self.recv_from_all()

			self.info("Leader has all ciphertexts")

			""" Leader must add own cipher to the set. """
			self.data_in.append(marshal.dumps((self.round_id,
							self.cipher)))

		else:
			self.info("Sending cipher to leader")
			self.send_to_leader(marshal.dumps((self.round_id,self.cipher)))
			self.info("Finished phase 2")


	def create_cipher_string(self):
		self.cipher_prime = self.datum_string()
		""" Encrypt with all secondary keys from N ... 1 """
		self.debug("Orig len: %d" % len(self.cipher_prime))
		
		for i in xrange(self.n_nodes - 1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher_prime = AnonCrypto.encrypt_with_rsa(k2, self.cipher_prime)
			self.debug("Cipher-prim len: %d" % len(self.cipher_prime))

		self.cipher = self.cipher_prime

		""" Encrypt with all primary keys from N ... 1 """
		for i in xrange(self.n_nodes-1, -1, -1):
			k1, k2 = self.pub_keys[i]
			self.cipher = AnonCrypto.encrypt_with_rsa(k1, self.cipher)
			self.debug("Cipher len: %d" % len(self.cipher))

	"""
	PHASE 3

	Anonymization.
	"""
		
	def run_phase3(self):
		self.advance_phase()
		self.info("Starting phase 3")

		"""
		Everyone (except leader) blocks waiting for msg from
		previous node in the group.
		"""
		if self.am_leader():
			pass
		if self.id == 1:
		 	self.debug("Node 1 waiting for ciphers from leader")
			self.data_in = marshal.loads(self.recv_from_socket(self.leader_socket))
		 	self.debug("Node 1 got ciphers from leader")
		if self.id > 1:
			self.debug("Node waiting for set of ciphers")
			self.data_in = marshal.loads(self.recv_once())
			self.debug("Got set of ciphers")

		""" Shuffle ciphertexts. """
		self.shuffle_and_decrypt()
		self.debug("Shuffled ciphers")
	
		outstr = marshal.dumps(self.data_out)
		if self.am_last():
			self.debug("Sending ciphers to leader")
			self.send_to_leader(outstr)
		elif self.am_leader():
			self.debug("Sending ciphers to node 1")
			self.send_to_socket(self.sockets[0], outstr)
		else:
			ip, port = self.next_addr
			self.send_to_addr(ip, port, outstr)
			self.debug("Sent set of ciphers")
		
		if self.am_leader():
			""" Leader waits for ciphers from member N. """
			self.final_ciphers = marshal.loads(
					self.recv_from_socket(self.sockets[self.n_nodes - 2]))
			self.debug("Got ciphers from other nodes len = %d" % len(self.final_ciphers))

	def shuffle_and_decrypt(self):
		random.shuffle(self.data_in)
		self.debug("Shuffling len = %d" % len(self.data_in))
		self.data_out = []
		for ctuple in self.data_in:
			(rem_round, ctext) = marshal.loads(ctuple)
			if rem_round != self.round_id:
				raise RuntimeError, "Mismatched round numbers (mine:%d, other:%d)" % (self.round_id, rem_round)

			new_ctext = AnonCrypto.decrypt_with_rsa(self.key1, ctext)	
			pickled = marshal.dumps((self.round_id, new_ctext))
			self.data_out.append(pickled)

	"""
	PHASE 4

	Verification.
	"""

	def run_phase4(self):
		self.advance_phase()
		if self.am_leader():
			self.debug("Leader broadcasting ciphers to all nodes")
			self.broadcast_to_all_nodes(marshal.dumps(self.final_ciphers))
			self.debug("Cipher set len %d" % (len(self.final_ciphers)))
		else:
			""" Get C' ciphertexts from leader. """
			self.final_ciphers = marshal.loads(self.recv_from_leader())

		"""
		self.final_ciphers holds an array of
		pickled (round_id, cipher_prime) tuples
		"""

		my_cipher_str = marshal.dumps((self.round_id, self.cipher_prime))

		go = False
		if my_cipher_str in self.final_ciphers:
			self.info("Found my ciphertext in set")
			go = True
		else:
			self.critical("ABORT! My ciphertext is not in set!")
			self.debug(self.final_ciphers)
			go = False
			raise RuntimeError, "Protocol violation: My ciphertext is missing!"

		hashval = AnonCrypto.hash_list(self.final_ciphers)
		go_msg = marshal.dumps((
					self.id,
					self.round_id,
					go,
					hashval))
		
		go_data = ''
		if self.am_leader():
			""" Collect go msgs """
			data = self.recv_from_all(False)
			
			""" Add leader's signed GO message to set """
			data.append(AnonCrypto.sign(self.id, self.key1, go_msg))
			go_data = marshal.dumps((data))
			self.broadcast_to_all_nodes(go_data)

		else:
			""" Send go msg to leader """
			self.send_to_leader(go_msg)
			go_data = self.recv_from_leader()
		
		self.check_go_data(hashval, go_data)
		self.info("All nodes report GO")
		return

	def check_go_data(self, hashval, pickled_list):
		go_lst = marshal.loads(pickled_list)
		for item in go_lst:
			""" Verify signature on "GO" message """
			item_str = AnonCrypto.verify(self.pub_keys, item)
			(r_id, r_round, r_go, r_hash) = marshal.loads(item_str)
			if r_round != self.round_id:
			 	raise RuntimeError, "Mismatched round numbers"
			if not r_go:
			 	raise RuntimeError, "Node %d reports failure!" % (r_id)
			if r_hash != hashval:
			 	raise RuntimeError, "Node %d produced bad hash!" % (r_id)
		return True

	"""
	PHASE 5

	Decryption.
	"""

	def run_phase5(self):
		self.advance_phase()

		mykeystr = AnonCrypto.sign(self.id, self.key1, marshal.dumps((
							self.id,
							self.round_id,
							AnonCrypto.priv_key_to_str(self.key2))))

		if self.am_leader():
			data = self.recv_from_all()
			
			""" Add leader's signed key to set """
			data.append(mykeystr)
			self.debug("Key data... len = %d" % len(data))
			self.broadcast_to_all_nodes(marshal.dumps(data))

		else:
			self.info('Sending key to leader')
			self.send_to_leader(mykeystr)
			data = marshal.loads(self.recv_from_leader())
			self.info("Got key set from leader, len = %d" % len(data))

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
			""" Verify signature on each key """
			item_str = AnonCrypto.verify(self.pub_keys, item)
			(r_id, r_roundid, r_keystr) = marshal.loads(item_str)
			if r_roundid != self.round_id:
				raise RuntimeError, 'Mismatched round numbers'
			priv_keys[r_id] = AnonCrypto.priv_key_from_str(r_keystr)

		plaintexts = []
		for cipher in self.final_ciphers:
			(r_round, cipher_prime) = marshal.loads(cipher)
			if r_round != self.round_id:
				raise RuntimeError, 'Mismatched round ids'
			for i in xrange(0, self.n_nodes):
				cipher_prime = AnonCrypto.decrypt_with_rsa(priv_keys[i], cipher_prime)
			plaintexts.append(self.unpackage_msg(cipher_prime))
		
		self.anon_data = plaintexts
		

	"""
	Network Utility Functions
	"""

	def recv_from_leader(self, verify = True):
		return self.recv_from_socket(self.leader_socket, verify)

	def recv_once(self, verify = True):
		d = AnonNet.recv_once(self.ip, self.port)
		if verify:
			d = AnonCrypto.verify(self.pub_keys, d)
		return d

	def recv_from_socket(self, sock, verify = True):
		d = AnonNet.recv_from_socket(sock)
		if verify:
			d = AnonCrypto.verify(self.pub_keys, d)
		return d

	def broadcast_to_all_nodes(self, msg, signed = True):
		if not self.am_leader():
			raise RuntimeError, 'Only leader can broadcast'

		if signed: outmsg = AnonCrypto.sign(self.id, self.key1, msg)
		else: outmsg = msg

		AnonNet.broadcast_using(self.sockets, AnonNet.send_to_socket, outmsg)

	def send_to_addr(self, ip, port, msg, signed = True):
		if signed: outmsg = AnonCrypto.sign(self.id, self.key1, msg)
		else: outmsg = msg

		AnonNet.send_to_addr(ip, port, outmsg)

	def send_to_leader(self, msg, signed = True):
		self.send_to_socket(self.leader_socket, msg, signed)

	def send_to_socket(self, sock, msg, signed = True):
		if signed: outmsg = AnonCrypto.sign(self.id, self.key1, msg)
		else: outmsg = msg
		AnonNet.send_to_socket(sock, outmsg)

	def recv_from_all(self, verify = True):
		if not self.am_leader():
			raise RuntimeError, 'Only leader can broadcast'

		indata = AnonNet.recv_from_n(self.sockets)
		if verify:
			outdata = []
			for d in indata:
				outdata.append(AnonCrypto.verify(self.pub_keys, d))
			return outdata
		else:
			return indata

	def setup_sockets(self):
		self.cleanup = True
		if self.am_leader():
			self.debug("Opening leader sockets")
			self.sockets = AnonNet.new_server_socket_set(self.ip, self.port, self.n_nodes - 1)

			data = self.recv_from_all(False)
			newsockets = [None] * (self.n_nodes - 1)
			for i in xrange(0, self.n_nodes - 1):
				s_id = marshal.loads(data[i])
				self.debug(s_id)
				newsockets[s_id - 1] = self.sockets[i]
			self.sockets = newsockets

			self.debug("Opened sockets to all nodes")
		else:
			l_ip, l_port = self.leader_addr
			self.debug("Opening client socket to leader")
			self.leader_socket = AnonNet.new_client_sock(l_ip, l_port)
			self.send_to_leader(marshal.dumps(self.id), False)
			self.debug("Opened client socket to leader")

	def cleanup_sockets(self):
		if self.cleanup:
			self.debug("Closing sockets")
			if self.am_leader():
				for s in self.sockets:
					self.debug(s.getsockname())
					s.close()
			else:
				self.debug(self.leader_socket.getsockname())
				self.leader_socket.close()


	"""
	Utility Functions 
	"""


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


