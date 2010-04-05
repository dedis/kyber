#
# ANONYMITY PROTOCOL NETWORK UTILITY FUNCTIONS
#

import socket, cPickle, random, struct, tempfile
from time import sleep
from logging import debug, info, critical

class AnonNet:
	MAX_ATTEMPTS = 20



#
# Big file functions
#

	@staticmethod
	def send_file_to_addr(ip, port, filename):
		sock = AnonNet.new_client_sock(ip, port)
		info("Connected to node")

		blocksize = 4096
		with open(filename, 'r') as f:
			while True:
				bytes = f.read(blocksize)
				if(bytes = '') break
				
				debug("Sending %d bytes" % (bytes))
				AnonNet.send_to_socket(sock, bytes)

		sock.close()
		debug('Closed socket to server')

	@staticmethod
	def recv_file_from_socket(sock):
		blocksize = 4096
		filename = tempfile.mkstemp()

		with open(filename, 'w') as f:
			while True:
				try:
					newdat = sock.read(blocksize)
				except KeyboardInterrupt, SystemExit:
					sock.close()

				# File is done
				if len(newdat) == 0: break

				debug("Got %d bytes" % len(newdat))
				f.write(newdat)
		sock.close()

		return filename

	def recv_files_from_n(server_ip, server_port, n_backlog):
		debug('Setting up server socket')

		# set up server connection 
		addrs = []
		server_sock = AnonNet.new_server_socket(
				server_ip, server_port, n_backlog)

		data = []
		for i in xrange(0, n_backlog):
			debug("Listening...")
			try:
				(rem_sock, (rem_ip, rem_port)) = server_sock.accept()
				addrs.append((rem_ip, rem_port))
			except KeyboardInterrupt:
				server_sock.close()
				raise
			data.append(AnonNet.recv_file_from_sock(rem_sock))
		server_sock.close()
		debug('Got all messages, closing socket')
		return (data, addrs)

#
# Misc Network
#

	@staticmethod
	def send_to_addr(ip, port, msg):
		sock = AnonNet.new_client_sock(ip, port)
		info("Connected to node")
		AnonNet.send_to_socket(sock, msg)
		sock.close()
		debug("Closed socket to server")

	@staticmethod
	def send_to_socket(sock, msg):
		# Snippet inspired by http://www.amk.ca/python/howto/sockets/
		totalsent = 0
		while totalsent < len(msg):
			try:
				sent = sock.send(msg[totalsent:])
			except KeyboardError, SystemExit:
				sock.close()
				raise
			debug("Sent %d bytes" % (sent))
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent
		return

	@staticmethod
	def recv_from_sock(sock):
		info("Reading from socket")
		data = ""
		while True:
			try:
				newdat = sock.recv(4096)
			except socket.error, (errno, errstr):
				if errno == 35: continue
				else: raise
			except KeyboardInterrupt:
			 	sock.close()
			 	raise
			if len(newdat) == 0: break
			data += newdat
		sock.close()
		return data

	@staticmethod
	def new_server_socket(ip, port, n_backlog):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(1)
		sock.settimeout(180.0)
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
				if errno == 61 or errno == 22: # Server not awake yet
					if i == AnonNet.MAX_ATTEMPTS - 1:
						raise RuntimeError, "Cannot connect to server"
					debug("Waiting for server...")
					sleep(random.randint(3,8))
					sock.close()
				else: raise
			except KeyboardInterrupt:
				sock.close()
				raise
		return sock

	@staticmethod
	def recv_from_n(my_ip, my_port, n_backlog):
		debug('Setting up server socket')

		# set up server connection 
		addrs = []
		server_sock = AnonNet.new_server_socket(my_ip, my_port, n_backlog)
		data = []
		for i in xrange(0, n_backlog):
			debug("Listening...")
			try:
				(rem_sock, (rem_ip, rem_port)) = server_sock.accept()
				addrs.append((rem_ip, rem_port))
			except KeyboardInterrupt:
				server_sock.close()
				raise
			data.append(AnonNet.recv_from_sock(rem_sock))
		server_sock.close()
		debug('Got all messages, closing socket')
		return (data, addrs)

