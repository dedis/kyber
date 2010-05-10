"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: utils.py
Description: Utility functions for the anon
protocol implementation.
Author: Henry Corrigan-Gibbs
"""

from __future__ import with_statement
from numpy import frombuffer, bitwise_xor, byte, uint64

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
		""" Quickly XOR two strings together using the numpy library """
		if len(str1) != len(str2):
			raise RuntimeError, 'Strings must be equal length'
		blocks = len(str1) / 64
		chars = len(str1) % 64

		sep = 64*blocks

		out = ''

		if blocks > 0:
			b1 = frombuffer(str1[:sep], dtype=uint64)
			b2 = frombuffer(str2[:sep], dtype=uint64)
			out = bitwise_xor(b1, b2).tostring()

		if chars > 0:
			b3 = frombuffer(str1[sep:], dtype=byte)
			b4 = frombuffer(str2[sep:], dtype=byte)
			out = out + bitwise_xor(b3, b4).tostring()

		return out

