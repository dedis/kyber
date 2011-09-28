"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: anon_crypto.py
Description: Crypto primitives for the anon protocol.
Author: Henry Corrigan-Gibbs
"""

from __future__ import with_statement
from utils import Utilities
from logging import debug
import tempfile, struct, marshal
from cStringIO import StringIO

import M2Crypto.EVP, M2Crypto.RSA, M2Crypto.Rand

class AnonCrypto: 
	""" A very unsecure initialization vector for AES. """
	AES_IV = 'al*73lf9)982'
	KEYFILE_PASSWORD = '12f*d4&^#)!-1728410df' 
	PRNG_SEED_LEN = 1024
	
	@ staticmethod
	def key_password(input):
		return AnonCrypto.KEYFILE_PASSWORD

	"""
	 RSA Encryption

	 We do this the standard way: 
	 1) Encrypt the msg with a random AES key
	 2) Encrypt the AES key with the RSA key
	 3) The ciphertext is the (encrypted-AES-key, AES-ciphertext) tuple
	"""
	
	@staticmethod
	def encrypt_with_rsa(pubkey, msg):
		session_key = M2Crypto.Rand.rand_bytes(32)
	
		"""
		AES must be padded to make 16-byte blocks
		Since we prepend msg with # of padding bits
		we actually need one less padding bit
		"""
		n_padding = ((16 - (len(msg) % 16)) - 1) % 16
		padding = '\0' * n_padding

		pad_struct = struct.pack('!B', n_padding)

		encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.encrypt)

		""" Output is tuple (E_rsa(session_key), E_aes(session_key, msg)) """
		enc_key = pubkey.public_encrypt(session_key, M2Crypto.RSA.pkcs1_oaep_padding)
		enc_msg = encrypt.update(pad_struct + msg + padding) 

		return enc_key + enc_msg

	@staticmethod
	def decrypt_with_rsa(privkey, cipherstr):
		enc_key = cipherstr[:128]	# First 128 bytes are the key
		enc_msg = cipherstr[128:]	# Rest is the padded AES ciphertext
		
		""" Get session key using RSA decryption """
		session_key = privkey.private_decrypt(enc_key, 
				M2Crypto.RSA.pkcs1_oaep_padding)
		
		""" Use session key to recover string """
		dummy_block =  ' ' * 8
		decrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.decrypt)

		outstr = decrypt.update(enc_msg) + decrypt.update(dummy_block)
		pad_data = outstr[0]
		outstr = outstr[1:]

		""" Get num of bytes added at end """
		n_padding = struct.unpack('!B', pad_data)
		
		""" Second element of tuple is always empty for some reason """
		n_padding = n_padding[0]
		outstr = outstr[:(len(outstr) - n_padding)]

		return outstr

	@staticmethod
	def encrypt_with_private_rsa(privkey, msg):
		session_key = M2Crypto.Rand.rand_bytes(32)
	
		"""
		AES must be padded to make 16-byte blocks
		Since we prepend msg with # of padding bits
		we actually need one less padding bit
		"""
		n_padding = ((16 - (len(msg) % 16)) - 1) % 16
		padding = '\0' * n_padding

		pad_struct = struct.pack('!B', n_padding)

		encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.encrypt)

		""" Output is tuple (E_rsa(session_key), E_aes(session_key, msg)) """
		enc_key = privkey.private_encrypt(session_key, M2Crypto.RSA.pkcs1_padding)
		enc_msg = encrypt.update(pad_struct + msg + padding) 

		return enc_key + enc_msg

	@staticmethod
	def decrypt_with_public_rsa(pubkey, cipherstr):
		enc_key = cipherstr[:128]	# First 128 bytes are the key
		enc_msg = cipherstr[128:]	# Rest is the padded AES ciphertext
		
		""" Get session key using RSA decryption """
		session_key = pubkey.public_decrypt(enc_key, 
				M2Crypto.RSA.pkcs1_padding)
		
		""" Use session key to recover string """
		dummy_block =  ' ' * 8
		decrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.decrypt)

		outstr = decrypt.update(enc_msg) + decrypt.update(dummy_block)
		pad_data = outstr[0]
		outstr = outstr[1:]

		""" Get num of bytes added at end """
		n_padding = struct.unpack('!B', pad_data)
		
		""" Second element of tuple is always empty for some reason """
		n_padding = n_padding[0]
		outstr = outstr[:(len(outstr) - n_padding)]

		return outstr

	@staticmethod
	def random_key(key_len):
		return M2Crypto.RSA.gen_key(key_len, 65537)

	"""
	Hash Function (We use SHA1)
	"""

	@staticmethod
	def hash(msg):
		h = M2Crypto.EVP.MessageDigest('sha1')
		h.update(msg)
		return h.final()

	@staticmethod
	def hash_list(lst):
		""" Get a hash value for a list """
		return AnonCrypto.hash(marshal.dumps(lst))

	@staticmethod
	def hash_file(filename):
		hash = M2Crypto.EVP.MessageDigest('sha1')
		with open(filename, 'r') as f:
			while True:
				bytes = f.read(4096)
				if bytes == '': break
				hash.update(bytes)
		return hash.final()


	"""
	RSA Signatures
	"""

	@staticmethod
	def sign(my_id, signkey, msg):
		return marshal.dumps(
				(my_id, msg,
				 signkey.sign(
					 AnonCrypto.hash(msg))))
		
	@staticmethod
	def verify(key_dict, msgstr):
		((r_id, msg, sig)) = marshal.loads(msgstr)
		if key_dict[r_id][0].verify(AnonCrypto.hash(msg), sig):
			return msg
		else:
		 	raise RuntimeError, 'Invalid Signature'

	@staticmethod
	def verify_with_key(key, msgstr):
		(msg, sig) = marshal.loads(msgstr)
		if key.verify(AnonCrypto.hash(msg), sig):
			return True
		else:
		 	return False

	@staticmethod
	def sign_with_key(signkey, msg):
		return marshal.dumps(
				(msg,
				 signkey.sign(
					 AnonCrypto.hash(msg))))

	"""
	I/O Utility Functions
	"""

	@staticmethod
	def priv_key_to_str(privkey):
		return privkey.as_pem(callback = AnonCrypto.key_password)

	@staticmethod
	def priv_key_from_str(key_str):
		(handle, filename) = tempfile.mkstemp()
		Utilities.write_str_to_file(filename, key_str)
		key = M2Crypto.RSA.load_key(filename, callback = AnonCrypto.key_password)
		if not key.check_key(): raise RuntimeError, 'Bad key decode'
		return key

	@staticmethod
	def pub_key_to_str(pubkey):
		(handle, filename) = tempfile.mkstemp()
		pubkey.save_key(filename)
		return Utilities.read_file_to_str(filename)

	@staticmethod
	def pub_key_from_str(key_str):
		(handle, filename) = tempfile.mkstemp()
		Utilities.write_str_to_file(filename, key_str)
		return M2Crypto.RSA.load_pub_key(filename)

	"""
	Pseudo-Random Number Generation

	We uses AES in counter mode to generate cryptographically
	strong random bitstrings.
	"""
	@staticmethod
	def random_seed():
		return M2Crypto.Rand.rand_bytes(AnonCrypto.PRNG_SEED_LEN)

	@staticmethod
	def random_file(length):
		handle, fname = tempfile.mkstemp()
		
		blocksize = 8192
		a = AnonRandom(M2Crypto.Rand.rand_bytes(32))
		lleft = length
		with open(fname, 'w') as f:
			while lleft > 0:
				if lleft < blocksize:
					f.write(a.rand_bytes(lleft))
				else:
					f.write(a.rand_bytes(blocksize))
				lleft = lleft - blocksize
		return fname

class AnonRandom:
	"""
		This class holds hash data and random state
		data for a pseduo-random bitstring.
	"""

	def __init__(self, seed):
		self.encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				seed, AnonCrypto.AES_IV, M2Crypto.encrypt)
		self.counter = 0
		self.hash = M2Crypto.EVP.MessageDigest('sha1')
	
	def rand_bytes(self, nbytes):
		blocks = nbytes / 16
		
		out = StringIO()
		for i in xrange(0, blocks):
			newblock = self.get_block()
			self.hash.update(newblock)
			out.write(newblock)

		if nbytes % 16 != 0:
			lastblock = self.get_block()
			lastbytes = lastblock[:(nbytes % 16)]
			self.hash.update(lastbytes)
			out.write(lastbytes)

		return out.getvalue()
	
	def get_block(self):
		self.encrypt.update(struct.pack('>Q', self.counter))
		self.counter = self.counter + 1
		return self.encrypt.final()

	def hash_value(self):
		return self.hash.final()
