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
