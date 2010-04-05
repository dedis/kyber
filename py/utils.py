# UTILITY FUNCTIONS

class Utilities:
	@staticmethod
	def read_file_to_str(filename):
		str = ""
		with open(filename, 'r') as f:
			for line in f:
				str += line
		return str

	@staticmethod
	def write_str_to_file(filename, msg):
		with open(filename, 'w') as f:
			f.write(msg)

	@staticmethod
	def xor_bytes(str1, str2):
		if len(str1) != len(str2):
			raise RuntimeError, 'Strings must be equal length'

		out = ''
		for i in xrange(0, len(str1)):
			out = out + chr(ord(str1[i]) ^ ord(str2[i]))
		return out

