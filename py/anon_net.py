"""
Filename: anon_net.py
Description: Networking utility functions for the
anon protocol implementation.
"""

import socket, cPickle, random, struct, tempfile, os
from time import sleep
from logging import debug, info, critical
import threading

class AnonNet:
	"""
	Maximum number of times a client will try to connect
	to a server node.
	"""
	MAX_ATTEMPTS = 1000

	LEN_FORMAT = "!Q"

	"""
	Big file functions

	Files in the bulk protocol may be very large, so we send
	them block by block.
	"""

	@staticmethod
	def send_file_to_addr(ip, port, filename):
		sock = AnonNet.new_client_sock(ip, port)
		info("Connected to node")

		blocksize = 4096
		with open(filename, 'r') as f:
			while True:
				bytes = f.read(blocksize)
				if(bytes == ''): break
				
				AnonNet.send_to_socket(sock, bytes)

		sock.close()
		debug('Closed socket to server')

	@staticmethod
	def recv_file_from_sock(sock):
		blocksize = 4096
		handle, filename = tempfile.mkstemp()

		with open(filename, 'w') as f:
			while True:
				try:
					newdat = sock.recv(blocksize)
				except KeyboardInterrupt, SystemExit:
					sock.close()
				except socket.error, (errno, errstr):
					if errno == 35: continue
					else: raise	

				# File is done
				if len(newdat) == 0: break

				f.write(newdat)
		return filename

	@staticmethod
	def recv_files_from_n(sockets):
		return AnonNet.threaded_recv_from_n(
				sockets,
				AnonNet.recv_file_from_sock)

	"""
	Misc Network
	"""

	@staticmethod
	def send_to_addr(ip, port, msg):
		debug("Trying to connect to %s:%d" % (ip,port))
		sock = AnonNet.new_client_sock(ip, port)
		debug("Connected to %s:%d" % (ip,port))
		AnonNet.send_to_socket(sock, msg)
		sock.close()
		debug("Closed socket to server")

	@staticmethod
	def send_to_socket(sock, msg):
		""" Snippet inspired by http://www.amk.ca/python/howto/sockets/ """
		AnonNet.send_bytes(sock, struct.pack(AnonNet.LEN_FORMAT, len(msg)))
		debug("Sent header len: %d" % len(msg))
		AnonNet.send_bytes(sock, msg)

	@staticmethod
	def recv_from_socket(sock):
		header_len = struct.calcsize(AnonNet.LEN_FORMAT)
		header = AnonNet.recv_bytes(sock, header_len)

		(msg_len,) = struct.unpack(AnonNet.LEN_FORMAT, header)
		return AnonNet.recv_bytes(sock, msg_len)

	@staticmethod
	def send_bytes(sock, bytes):
		fd = sock.fileno()
		totalsent = 0
		while totalsent < len(bytes):
			try:
				sent = os.write(fd, bytes[totalsent:])
			except KeyboardInterrupt, SystemExit:
				sock.close()
				raise
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent
		return

	@staticmethod
	def recv_bytes(sock, n_bytes):
		fd = sock.fileno()

		debug("Reading %d bytes from socket" % n_bytes)
		data = ""
		blocksize = 4096
		to_read = n_bytes
		while to_read > 0:
			try:
				newdat = os.read(fd, min(blocksize, to_read))
			except socket.error, (errno, errstr):
				if errno == 35: continue
				else: raise
			except KeyboardInterrupt, SystemExit:
			 	sock.close()
			 	raise
			if len(newdat) == 0:
			 	raise RuntimeError, "Socket closed unexpectedly"
			to_read = to_read - len(newdat)
			debug("Read %d bytes, waiting for %d more" % (len(newdat), to_read))
			data += newdat
		return data

	@staticmethod
	def recv_once(my_ip, my_port):
		debug("Setting up server socket at %s:%d" % (my_ip, my_port))
		sock_list = AnonNet.new_server_socket_set(my_ip, my_port, 1)
		s = sock_list[0]
		debug("Set up server socket at %s:%d" % (my_ip, my_port))
		d = AnonNet.recv_from_socket(s)
		s.close()
		return d

	@staticmethod
	def recv_file_once(my_ip, my_port):
		s = AnonNet.new_client_sock(my_ip, my_port)
		f = AnonNet.recv_file_from_sock(s)
		s.close()
		return f

	@staticmethod
	def new_server_socket(ip, port, n_backlog):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(1)
		sock.settimeout(None)
		try:
			sock.bind((ip, port))
		except socket.error, (errno, errstr):
			if errno == 48: critical('Leader cannot bind port')
			raise
		sock.listen(n_backlog)
		debug("Socket listening at %s:%d" % (ip, port))
		return sock

	@staticmethod
	def new_client_sock(ip, port):
		debug("Trying to connect to (%s, %d)" % (ip, port))
		for i in xrange(0, AnonNet.MAX_ATTEMPTS):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				sock.connect((ip, port))
				break
			except socket.error, (errno, errstr):
				if errno == 61 or errno == 22 or errno == 111: # Server not awake yet
					if i == AnonNet.MAX_ATTEMPTS - 1:
						raise RuntimeError, "Cannot connect to server"
					debug("Waiting for server %s:%d..." % (ip,port))
					sleep(random.randint(5,10))
					sock.close()
				else: raise
			except KeyboardInterrupt:
				sock.close()
				raise
		return sock

	@staticmethod
	def recv_from_n(sockets):
		return AnonNet.threaded_recv_from_n(
				sockets,
				AnonNet.recv_from_socket)


	"""
	Threaded Net functions
	"""

	@staticmethod
	def broadcast_using(sockets, func, arg):
		threads = []

		""" Only leader can broadcast """
		for i in xrange(0, len(sockets)):
			t = threading.Thread(
					target = func,
					args = (sockets[i], arg))
			debug("Starting thread %s" % t.name)
			t.start()
			threads.append(t)
#func(ip, port, arg)	

		for t in threads:
			debug("Joining thread %s" % t.name)
			t.join()

	@staticmethod
	def threaded_recv_from_n(sockets, sock_function):
		""" Receive a message from N nodes """

		debug('Setting up server socket')

		""" Set up server connection """
		data = [None] * len(sockets)
		threads = []
		for i in xrange(0, len(sockets)):
			t = threading.Thread(
				target = AnonNet.read_sock_into_array,
				args = (data, i, sock_function, sockets[i]))
			t.start()
			threads.append(t)

		for t in threads:
			t.join()
		
		debug("Got %d messages" % len(data))
		return data

	@staticmethod
	def	new_server_socket_set(server_ip, server_port, n_clients):
		debug('Setting up server socket')
		""" Set up server connection """
		server_sock = AnonNet.new_server_socket(server_ip, server_port, n_clients)
		socks = []
		for i in xrange(0, n_clients):
			debug("Listening...")
			try:
				(rem_sock, (rem_ip, rem_port)) = server_sock.accept()
				socks.append(rem_sock)
			except KeyboardInterrupt:
				server_sock.close()
				raise
		server_sock.close()

		debug('Got all messages, closing socket')

		return socks

	@staticmethod
	def read_sock_into_array(data_array, index, sock_function, sock):
		data_array[index] = sock_function(sock)

