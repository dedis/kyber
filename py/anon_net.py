#
# ANONYMITY PROTOCOL NETWORK UTILITY FUNCTIONS
#

import socket, cPickle, random, struct
from time import sleep
from logging import debug, info, critical

class AnonNet:
	@staticmethod
	def send_to_addr(ip, port, msg):
		debug("Trying to connect to (%s, %d)" % (ip, port))
		for i in xrange(0, 20):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				sock.connect((ip, port))
				break
			except socket.error, (errno, errstr):
				if errno == 61 or errno == 22: # Server not awake yet
					if i == 9:
						raise RuntimeError, "Cannot connect to server"
					debug("Waiting for server...")
					sleep(random.randint(3,8))
					sock.close()
				else: raise
			except KeyboardInterrupt:
				sock.close()
				raise

		info("Connected to node")
		AnonNet.send_to_socket(sock, msg)
		sock.close()
		debug("Closed socket to server")

	@staticmethod
	def send_to_socket(sock, msg):
		# Snippet inspired by http://www.amk.ca/python/howto/sockets/
		totalsent = 0
		while totalsent < len(msg):
			sent = sock.send(msg[totalsent:])
			debug("Sent %d bytes" % (sent))
			if sent == 0:
				raise RuntimeError, "Socket broken"
			totalsent = totalsent + sent
		return

	@staticmethod
	def recv_from_sock(sock, ip, port):
		info("Reading from %s:%d" % (ip, port)) 
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
			data.append(AnonNet.recv_from_sock(rem_sock, rem_ip, rem_port))
		server_sock.close()
		debug('Got all messages, closing socket')
		return (data, addrs)

