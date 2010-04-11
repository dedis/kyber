#
# CRYPTO PRIMITIVES FOR ANON PROTOCOL
#

import M2Crypto.EVP, M2Crypto.RSA, M2Crypto.Rand
from utils import Utilities
import tempfile, struct, cPickle, base64
from logging import debug
from cStringIO import StringIO

class AnonCrypto: 
	# A very unsecure initialization vector
	AES_IV = 'al*73lf9)982'
	KEYFILE_PASSWORD = '12f*d4&^#)!-1728410df' 
	PRNG_SEED_LEN = 1024

	
	@ staticmethod
	def key_password(input):
		return AnonCrypto.KEYFILE_PASSWORD

#
# RSA Encryption
#
# We do this the standard way: 
# 1) Encrypt the msg with a random AES key
# 2) Encrypt the AES key with the RSA key
# 3) The ciphertext is the (encrypted-AES-key, AES-ciphertext) tuple
#

	@staticmethod
	def encrypt_with_rsa(pubkey, msg):
		session_key = M2Crypto.Rand.rand_bytes(32)
	
		# AES must be padded to make 16-byte blocks
		# Since we prepend msg with # of padding bits
		# we actually need one less padding bit
		n_padding = ((16 - (len(msg) % 16)) - 1) % 16
		padding = '\0' * n_padding

		pad_struct = struct.pack('!B', n_padding)

		encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.encrypt)

		# Output is tuple (E_rsa(session_key), E_aes(session_key, msg))
		enc_key = pubkey.public_encrypt(session_key, M2Crypto.RSA.pkcs1_oaep_padding)
		enc_msg = encrypt.update(pad_struct + msg + padding) 

		return enc_key + enc_msg

	@staticmethod
	def decrypt_with_rsa(privkey, cipherstr):
		enc_key = cipherstr[:128]	# First 128 bytes are the key
		enc_msg = cipherstr[128:]	# Rest is the padded AES ciphertext
		
		# Get session key using RSA decryption
		session_key = privkey.private_decrypt(enc_key, 
				M2Crypto.RSA.pkcs1_oaep_padding)
		
		# Use session key to recover string
		dummy_block =  ' ' * 8
		decrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				session_key, AnonCrypto.AES_IV, M2Crypto.decrypt)

		outstr = decrypt.update(enc_msg) + decrypt.update(dummy_block)
		pad_data = outstr[0]
		outstr = outstr[1:]

		# Get num of bytes added at end
		n_padding = struct.unpack('!B', pad_data)
		
		# Second element of tuple is always empty for some reason
		n_padding = n_padding[0]
		outstr = outstr[:(len(outstr) - n_padding)]

		return outstr

	@staticmethod
	def random_key(key_len):
		return M2Crypto.RSA.gen_key(key_len, 65537)

#
# HASH Function (We use SHA1)
#

	@staticmethod
	def hash(msg):
		h = M2Crypto.EVP.MessageDigest('sha1')
		h.update(msg)
		return h.final()

	# Get a hash value for a list
	@staticmethod
	def hash_list(lst):
		return AnonCrypto.hash(cPickle.dumps(lst))

	@staticmethod
	def hash_file(filename):
		hash = M2Crypto.EVP.MessageDigest('sha1')
		with open(filename, 'r') as f:
			while True:
				bytes = f.read(4096)
				if bytes == '': break
				hash.update(bytes)
		return hash.final()


#
# Signatures
#

	@staticmethod
	def sign(my_id, signkey, msg):
		return cPickle.dumps(
				(my_id, msg,
				 signkey.sign(
					 AnonCrypto.hash(msg))))
		
	@staticmethod
	def verify(key_dict, msgstr):
		((r_id, msg, sig)) = cPickle.loads(msgstr)
		if key_dict[r_id][0].verify(AnonCrypto.hash(msg), sig):
			return msg
		else:
		 	raise RuntimeError, 'Invalid Signature'



#
# Random Numbers
#

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




#
# I/O Utility Functions
#

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

#
# Random Strings (Uses AES in counter mode)
#

class AnonRandom:
	def __init__(self, seed):
		self.encrypt = M2Crypto.EVP.Cipher('aes_256_cbc', 
				seed, AnonCrypto.AES_IV, M2Crypto.encrypt)
		self.counter = 0
		self.hash = M2Crypto.EVP.MessageDigest('sha1')
	
	def rand_bytes(self, nbytes):
		### TEMP ###
#return 'L' * nbytes

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
