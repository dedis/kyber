from __future__ import with_statement

import os.path, random, socket, sys, hashlib, marshal, SocketServer, threading, copy, time, subprocess

from anon_crypto import AnonCrypto
from anon_net import AnonNet
from utils import Utilities
import shuffle_node
import bulk_node

import M2Crypto.RSA

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

KEY_LENGTH = 1024
DEFAULT_PORT = 9000
INTEREST_WAIT = 1
PREPARE_WAIT = 1
DEFAULT_LENGTH = 128

class Net(QThread):
    def __init__(self, parent):
        QThread.__init__(self)
        self.nodes = []
        self.privKey = ''
        self.pubKey = ''
        self.shared_filename = ''
        self.participants = []
        self.distrusted_peers = []

        #load up your priv/pub keypair
        self.establish_keys()

        # read in peers from peers file
        self.establish_peers()

        # save ip, port, and hashkey for yourself
        self.ip = self.get_my_ip()
        self.gui_port, self.com_port = self.get_my_port()
        print "gui port: %s -- com port: %s" % (self.gui_port, self.com_port)
        self.hashkey = self.hash_peer(self.ip, self.gui_port)

        # created threaded server
        self.server = ThreadedServer((self.ip, self.gui_port), self.handler_factory())
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        self.DEBUG(str(self.ip) + ":" + str(self.gui_port))
    
    # need to implement this because Net subclasses QThread
    def run(self):
        pass

    """ GUI intiiated round """
    def initiate_round(self):
        self.DEBUG("I initiated a dissent round! Finding collaborators...")

        # get the path to the file you want to share
        self.emit(SIGNAL("getSharedFilename()"))
        nonce = int(1)
        self.participants = []
        self.distrusted_peers = []

        """ generate temporary keys for this round, add to participants """
        self.gen_temp_keys()
        temp1_str = AnonCrypto.pub_key_to_str(self.pubgenkey1)
        temp2_str = AnonCrypto.pub_key_to_str(self.pubgenkey2)

        """ initiate round with a signed voucher containing relevant information """
        my_voucher = marshal.dumps((nonce,self.ip,self.gui_port,self.com_port,temp1_str,temp2_str))
        cipher = AnonCrypto.sign_with_key(self.privKey, my_voucher)

        """ make sure you have something to share first """
        if os.path.exists(self.shared_filename):
            self.DEBUG("You are sharing file %s" % (self.shared_filename))
        else:
            self.DEBUG("Not a valid file path, share something to start a round!")
            return

        # add yourself as leader in the participants list (entry 0)
        self.participants.append((cipher, self.ip, self.gui_port, self.com_port))
        self.emit(SIGNAL("getDistrustedPeers()"))

        # ask if peers are interested
        interest_voucher = marshal.dumps((nonce, self.ip, self.gui_port, self.com_port))
        cipher = AnonCrypto.sign_with_key(self.privKey, interest_voucher)
        self.broadcast_to_all_peers(marshal.dumps(("interested?",cipher)))

        # allow one minute to receive all replies, then initiate round with those peers
        DelayTimer(INTEREST_WAIT, self.prepare_round).start()

    """ respond if you're going to participate in a round """
    def recv_interest_voucher(self, data):
        msg, key = marshal.loads(data)
        (nonce, leader_ip, leader_gui_port, leader_com_port) = marshal.loads(msg)
        self.DEBUG("Start round voucher from %s:%s, communicating at port %s" % (leader_ip, leader_gui_port, leader_com_port))

        # get the path to the file you want to share
        self.emit(SIGNAL("getSharedFilename()"))

        verified = self.verify(leader_ip, leader_gui_port, data)

        """ generate temporary keys for this round so leader can aggregate """
        self.gen_temp_keys()
        temp1_str = AnonCrypto.pub_key_to_str(self.pubgenkey1)
        temp2_str = AnonCrypto.pub_key_to_str(self.pubgenkey2)

        """ default to random file of 128 bytes if you don't have anything to share """
        if verified:
            if os.path.exists(self.shared_filename):
                self.DEBUG("You are sharing file %s" % (self.shared_filename))
            else:
                self.DEBUG("Not a valid file path, continuing without sharing...")

            # respond with your interest
            self.DEBUG("Verified leader, participating as %s:%s at port %s" % (self.ip, self.gui_port, self.com_port))
            response = marshal.dumps((nonce,self.ip,self.gui_port,self.com_port,temp1_str,temp2_str))
            cipher = AnonCrypto.sign_with_key(self.privKey, response)
            AnonNet.send_to_addr(leader_ip, int(leader_gui_port), marshal.dumps(("interested", cipher)))
        else:
            self.DEBUG("Unkown leader, opting out...")

    """ leader has received an interest voucher """
    def recv_interested(self, data):
        msg, key = marshal.loads(data)
        (nonce, interest_ip, interest_gui_port, interest_com_port, pubkey1_str, pubkey2_str) = marshal.loads(msg)

        self.distrusted_peers = []

        verified = self.verify(interest_ip, interest_gui_port, data)

        # if verified, add to participants vector and retreive distrusted peerlist
        if verified:
            self.DEBUG("%s:%s verified communicating at port %s" % (interest_ip, interest_gui_port, interest_com_port))
            self.emit(SIGNAL("getDistrustedPeers()"))
            self.participants.append((data, interest_ip, interest_gui_port, interest_com_port))
        else:
            self.DEBUG("Interest from %s:%s not verified!" % (interest_ip, interest_gui_port))

    """ called INTEREST_WAIT minutes after GUI-initiated round """
    def prepare_round(self):
        # can't start round without 3 or more peers
        if len(self.participants) < 3:
            self.DEBUG("Not enough peers to start round!")
            return

        prepare_voucher = marshal.dumps((int(PREPARE_WAIT),int(1),copy.copy(self.participants), self.ip, self.gui_port, self.com_port))
        cipher = AnonCrypto.sign_with_key(self.privKey, prepare_voucher)

        for index, participant in enumerate(self.participants):
            down_index = (index - 1) % len(self.participants)
            up_index = (index + 1) % len(self.participants)
            if (self.ip, self.gui_port, self.com_port) != (participant[1], participant[2], participant[3]):
                AnonNet.send_to_addr(participant[1], participant[2], \
                        marshal.dumps(("prepare:%s:%s:%s"%(index, down_index, up_index),cipher)))
                self.DEBUG("Sending prepare to peer %s:%s at port %s" % (participant[1], participant[2], participant[3]))

        # after informing the participants, create your node
        dn_idx = -1 % len(self.participants)
        up_idx = 1
        self.start_node(dn_idx, up_idx, self.participants, 0)

        # start round after PREPARE_WAIT minutes
        DelayTimer(PREPARE_WAIT, self.run_protocol).start()

    """ initializes node for running the protocol if verified leader """
    def recv_prepare(self, data, link_structure):
        msg, key = marshal.loads(data)
        (time, nonce, participants_vector, leader_ip, leader_gui_port, leader_com_port) = marshal.loads(msg)

        junk, my_id, down_index, up_index = link_structure.split(':')
        my_id, down_index, up_index = int(my_id), int(down_index), int(up_index)

        verified = self.verify(leader_ip, leader_gui_port, data)

        # if verified start node and run protocol after TIME minutes
        if verified:
            self.DEBUG("Ready to prepare! down: %s, up: %s, id: %s" % (down_index,up_index, my_id))
            self.start_node(down_index, up_index, participants_vector, my_id)
            DelayTimer(time, self.run_protocol).start()
        else:
            self.DEBUG("Leader not verified")


    """ prepares a node to be run via start_protocol() """
    def start_node(self, down_index, up_index, participants_vector, my_id):
        n_nodes = len(participants_vector)
        leader_addr = (participants_vector[0][1], int(participants_vector[0][3]))
        my_addr = (participants_vector[my_id][1], int(participants_vector[my_id][3]))
        dn_addr = (participants_vector[down_index][1], int(participants_vector[down_index][3]))
        up_addr = (participants_vector[up_index][1], int(participants_vector[up_index][3]))
        round_id = 1
        key_len = KEY_LENGTH

        """ if distrusted peer is participating, then don't share file (if one is chosen) """
        self.DEBUG("Distrusted peers: %s" % self.distrusted_peers)
        msg_file = None
        trusted = True
        if os.path.exists(self.shared_filename):
            for peer in participants_vector:
                for distrusted_peer in self.distrusted_peers:
                    (d_ip, d_port) = distrusted_peer
                    (p_ip, p_port) = peer[1], peer[2]
                    if d_ip == p_ip and str(d_port) == str(p_port):
                        self.DEBUG("Not sharing my file because peer %s:%s is participating" % (p_ip, p_port))
                        trusted = False
                        break
                if not trusted: break

        # create random file if none has been shared
        if trusted and os.path.exists(self.shared_filename):
            msg_file = self.shared_filename
        else:
            msg_file = AnonCrypto.random_file(DEFAULT_LENGTH)

        # initialize node
        self.node = bulk_node.bulk_node(my_id, key_len, round_id, n_nodes, \
                my_addr, leader_addr, dn_addr, up_addr, msg_file, participants_vector, self.privgenkey1, self.privgenkey2)
        self.DEBUG("round_id: %s id: %s n_nodes: %s my_addr: %s leader_addr: %s dn_addr: %s up_addr: %s msg_file: %s" % \
                (round_id, my_id, n_nodes, my_addr, leader_addr, dn_addr, up_addr, msg_file))

    def run_protocol(self):
        self.node.run_protocol()
        fnames = self.node.output_filenames()

    """ generates the two temp keys required for protocol """
    def gen_temp_keys(self):
        key1 = AnonCrypto.random_key(KEY_LENGTH)
        key2 = AnonCrypto.random_key(KEY_LENGTH)

        key1.save_key('config/temp1.priv', None)
        key1.save_pub_key('config/temp1.pub')

        key2.save_key('config/temp2.priv', None)
        key2.save_pub_key('config/temp2.pub')

        self.privgenkey1 = M2Crypto.RSA.load_key('config/temp1.priv')
        self.pubgenkey1 = M2Crypto.RSA.load_pub_key('config/temp1.pub')

        self.privgenkey2 = M2Crypto.RSA.load_key('config/temp2.priv')
        self.pubgenkey2 = M2Crypto.RSA.load_pub_key('config/temp2.pub')

    """ GUI initiated user expellation """
    def expel_peer(self, ip, port):
        self.DEBUG("IP/PORT to expel: %s:%s" % (ip, port))

        # create voucher for peers to save
        expel_voucher = marshal.dumps((self.ip, self.gui_port, ip, port, self.peer_public_key_string(ip,port)))
        cipher = AnonCrypto.sign_with_key(self.privKey, expel_voucher)
        self.broadcast_to_all_peers(marshal.dumps(("expel",cipher)))

        # remove from peerlist
        index = self.nodes.index((ip, int(port), self.peer_public_key_string(ip,port)))
        self.nodes.pop(index)
        self.update_peerlist()
        self.DEBUG("Expelled!")

        # save the voucher you sent out
        self.save_voucher(self.ip,self.gui_port,cipher,"expelvoucher")
    
    """ delete expelled peer from list given a proper voucher. save the voucher """
    def recv_expel_voucher(self, data):
        msg, key = marshal.loads(data)
        (vouch_ip, vouch_port, expel_ip, expel_port, expel_pubkey) = marshal.loads(msg)
        self.DEBUG("Recieved a expel voucher from %s:%s against %s:%s" % (vouch_ip, vouch_port, expel_ip, expel_port))

        # verify the expel voucher
        verified = self.verify(vouch_ip, vouch_port, data)

        # if verified, remove and save voucher
        if verified:
            try:
                index = self.nodes.index((expel_ip, int(expel_port), expel_pubkey))
                self.nodes.pop(index)
                self.DEBUG("Expelled!")
                self.update_peerlist()
            except:
                if self.ip == expel_ip and int(self.gui_port) == int(expel_port):
                    self.nodes = []
                    self.update_peerlist()
                    self.DEBUG("I'm being booted :(")
                else:
                    self.DEBUG("Booting someone I don't know")
            self.save_voucher(vouch_ip,vouch_port,data,"expelvoucher")
        else:
            self.DEBUG("Not a valid voucher -- not expelling")

    """ GUI initiated clique dropout """
    def drop_out(self):
        self.DEBUG("Dropping out of the clique")

        # create dropout voucher (IP, PORT, PUBKEY)
        dropout_voucher = marshal.dumps((self.ip, self.gui_port, self.public_key_string()))

        # sign it
        cipher = AnonCrypto.sign_with_key(self.privKey, dropout_voucher)

        # give all peers signed voucher of your voluntary quitting
        self.broadcast_to_all_peers(marshal.dumps(("quit", cipher)))

        # empty peerlist and exit
        self.nodes = []
        self.update_peerlist()

    """ Delete verified peer from list given a proper voucher. Save the voucher. """
    def recv_quit_voucher(self, data):
        msg, key = marshal.loads(data)
        (ip, port, pubkey_string) = marshal.loads(msg)
        self.DEBUG("Recieved a dropout voucher from %s:%s" % (ip, port))

        # verify quit voucher
        verified = self.verify(ip, port, data)
        
        # try to remove if verified, then save voucher
        if verified:
            try:
                index = self.nodes.index((ip, int(port), pubkey_string))
                self.nodes.pop(index)
                self.DEBUG("Verified Peer %s:%s is dropping out! Index: %s" % (ip, port, index))
                self.update_peerlist()
            except:
                self.DEBUG("Verified Peer %s:%s is not on your list!" % (ip, port))
            self.save_voucher(ip,port,data,"dropoutvoucher")
        else:
            self.DEBUG("Peer %s:%s not verified" % (ip, port))

    """
    GUI initiated invite
    """
    def invite_peer(self, ip, port):
        # if we have the peer's public key, initiate phase, otherwise warn user
        pubkey = self.hash_peer(ip, port)
        if not os.path.isfile("state/%s.pub" % pubkey):
            self.DEBUG("(%s, %i, %s) has no public key reference, yet" % (ip, port, pubkey))
        else:
            self.DEBUG("(%s, %i, %s) exists!" % (ip, port, pubkey))
            self.invite_phase(ip, port, pubkey)

    """ Phase 0: receive an invite from a peer """
    def recv_invite(self, data):
        # receive data
        msg, key = marshal.loads(data)

        # get (nonce, num_peers, peer_vector from msg) to verify msg
        (nonce, num_peers, peer_vector) = marshal.loads(msg)

        # parse out sender's ip/port to get saved pubkey, then verify
        ip, port = peer_vector[0][0], peer_vector[0][1]
        verified = self.verify(ip, port, data)

        if verified:
            # save the list of peers sent to you if verified
            self.DEBUG("verified invite contents: %s, %s, %s, %s" % (nonce, num_peers, peer_vector, verified))
            self.save_peer_list(peer_vector)

            # update GUI list
            self.update_peerlist()

            #send response
            self.accept_phase(ip, port, nonce)
        else:
            self.DEBUG("received invite not verifiable!")

    """ Phase 1: Send signed (nonce, N, vector(I)) tuple to invitee """
    def invite_phase(self, ip, port, pubkey):
        # create nonce, # peers, vector containing (ip, port, pubkey) of all peers
        nonce = 1
        num_peers = len(self.nodes) + 1
        peer_vector = [(self.ip,self.gui_port,self.public_key_string())]
        for node in self.nodes:
            hashkey = self.hash_peer(node[0], node[1])
            if hashkey != self.hashkey:
                peer_vector.append(node)

        # package the text up into (nonce, N, [array of peer data])
        invite = marshal.dumps((nonce,num_peers,peer_vector))

        # sign it
        cipher = AnonCrypto.sign_with_key(self.privKey, invite)

        # send to invitee packaged with who it's coming from ((ip:port), signed(text))
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("invite", cipher)))

    """ Phase 2: Respond to invite with signed (nonce, ip, port) tuple """
    def accept_phase(self, ip, port, nonce):
        # package and encrypt data
        response = marshal.dumps((nonce,self.ip,self.gui_port))
        cipher = AnonCrypto.sign_with_key(self.privKey, response)

        # respond with ((ip, port), encrypted_data)
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("accept", cipher)))

    """ Phase 3: Inform others (after validating response) """
    def inform_phase(self, data):
        msg, key = marshal.loads(data)

        # get corresponding public key to verify
        (recv_nonce, new_ip, new_port) = marshal.loads(msg)
        verified = self.verify(new_ip, new_port, data)

        # decrypt and validate!
        self.DEBUG("INFORMING: %s, %s, %s, %s" % (recv_nonce, new_ip, new_port, verified))
        if verified:
            self.DEBUG("SUCCESSFULLY INVITED/VALIDATED!")
            self.add_peer(new_ip, new_port)

            self.update_peerlist()

        # broadcast to all peers, save voucher
        voucher = marshal.dumps((self.ip, self.gui_port, new_ip, new_port, self.peer_public_key_string(new_ip, new_port)))
        sig_voucher = AnonCrypto.sign_with_key(self.privKey, voucher)
        self.save_voucher(new_ip, new_port, sig_voucher, "voucher")
        self.broadcast_to_all_peers(marshal.dumps(("inform", sig_voucher)))

    """ Phase 4: Someone just invited and vouched for a new peer """
    def recv_voucher(self, data):
        msg, key = marshal.loads(data)

        # get corresponding public key to verify
        (vouch_ip, vouch_port, new_ip, new_port, pub_key_string) = marshal.loads(msg)
        verified = self.verify(vouch_ip, vouch_port, data)

        self.DEBUG("Received voucher from %s:%s for %s:%s" % (vouch_ip, vouch_port, new_ip, new_port))

        # save voucher and add peer to nodelist if vouched properly
        if verified:
            self.DEBUG("SUCCESSFULLY VOUCHED")
            self.save_voucher(new_ip, new_port, data, "voucher")
            self.save_peer_key(new_ip, new_port, pub_key_string)
            self.add_peer(new_ip, new_port)

            self.update_peerlist()
        else:
            self.DEBUG("voucher not verified, no action taken")

    # verify peer with ip:port sending signed data
    def verify(self, ip, port, data):
        hashkey = self.hash_peer(ip, port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        return AnonCrypto.verify_with_key(pubkey, data)

    # save a voucher received over the network
    def save_voucher(self, ip, port, voucher, voucher_type):
        hashkey = self.hash_peer(ip, port)
        f = open("state/%s.%s" % (hashkey, voucher_type), 'w')
        f.write(voucher)
        f.close()

    # save the peer list sent during invite phase
    def save_peer_list(self, peer_vector):
        for peer in peer_vector:
            hashkey = self.hash_peer(peer[0], peer[1])
            if hashkey != self.hashkey:
                Utilities.write_str_to_file("state/%s.pub" % hashkey, peer[2])
                self.add_peer(peer[0], peer[1])

    # save a peers pubkey string sent over network
    def save_peer_key(self, ip, port, pub_key_string):
        hashkey = self.hash_peer(ip, port)
        Utilities.write_str_to_file("state/%s.pub" % hashkey, pub_key_string)

    # broadcast message to everyone in peer list
    def broadcast_to_all_peers(self, voucher):
        for node in self.nodes:
            ip, port = node[0], node[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((ip,int(port)))
                AnonNet.send_to_socket(sock, voucher)
                sock.close()
            except:
                self.DEBUG("peer %s:%s not available" % (ip, port))

    # create/load necessary files to save peer state
    def establish_peers(self):
        # parse peers if already exist
        if os.path.exists('state') and os.path.isfile('state/peers.txt'):
            self.DEBUG("parsing peers.txt")
            self.nodes = self.parse_peers('state/peers.txt')
            self.DEBUG(str(self.nodes))
            return

        # otherwise, create peers file for later
        if not os.path.exists('state'):
            os.mkdir('state')
        if not os.path.isfile('state/peers.txt'):
            self.DEBUG("creating peers.txt")
            open('state/peers.txt','w').close()

    # load / create your pub and priv keys in the config folder	
    def establish_keys(self):
        if not os.path.exists('config'):
            os.mkdir('config')
        try:
            # load them into instance vars if they already exist
            self.load_keys()
        except:
            # generate new keys, save them to config/priv
            # and config/pub -- then load them into instance vars
            self.DEBUG("keys don't exist/valid")
            newKey = AnonCrypto.random_key(KEY_LENGTH)
            self.save_keys(newKey)
            self.load_keys()

    # returns ip of host as string
    def get_my_ip(self):
        return socket.gethostbyname(socket.gethostname())

    # retrieve port value specified in config/port
    def get_my_port(self):
        try:
            # if port file exists, return it
            return self.load_port()
        except:
            # generate port file with default value
            self.DEBUG("port file doesn't exist, defaulting to " + str(DEFAULT_PORT))
            f = open('config/port', 'w')
            f.write("%s %s" % (str(DEFAULT_PORT), str(DEFAULT_PORT + 2000)))
            f.close()
            return [int(DEFAULT_PORT), int(DEFAULT_PORT + 2000)]

    # returns port from file as integer
    def load_port(self):
        with open('config/port') as f:
            for line in f:
                parts = line.split(' ')
                return [int(parts[0]), int(parts[1])]

    """
    parses peer.txt for ip and port then
    adds (ip,port,sha1(ip:port)) tuple to nodes.
    the public key of that peer will then be saved
    to state/hashstring.pub
    """
    def parse_peers(self, filename):
        nodes = []
        with open(filename, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, port = socket.gethostbyname(parts[0]), int(parts[1])
                nodes.append((ip,port,self.peer_public_key_string(ip,port)))
        return nodes

    # returns hash of ip:port peer
    def hash_peer(self, ip, port):
        port = int(port)
        return hashlib.sha1("%s" % ((ip,port),)).hexdigest()

    # send debug notifications to GUI
    def DEBUG(self, msg):
        self.emit(SIGNAL("messageReceived(QString)"), QString(msg))

    # add peer to self.nodes -- make sure its not you!
    def add_peer(self, ip, port):
        hashkey = self.hash_peer(ip, port)
        if hashkey != self.hashkey:
            self.nodes.append((ip,int(port),self.peer_public_key_string(ip,port)))

    def update_peerlist(self):
        peer_f = open('state/peers.txt','w')
        for peer in self.nodes:
            hashkey = self.hash_peer(peer[0], peer[1])
            if hashkey != self.hashkey:
                peer_f.write("%s %s\n" % (socket.gethostbyaddr(peer[0])[0], peer[1]))
        self.emit(SIGNAL("updatePeers()"))

    # saves public and private keys to local config directory
    def save_keys(self, rsa_key):
        rsa_key.save_key('config/priv', None)
        rsa_key.save_pub_key('config/pub')

    # loads pubkeys to file
    def load_keys(self):
        self.privKey = M2Crypto.RSA.load_key('config/priv')
        self.pubKey = M2Crypto.RSA.load_pub_key('config/pub')

    # print public key as string		
    def public_key_string(self):
        return AnonCrypto.pub_key_to_str(self.pubKey)

    # return peer public key as string
    def peer_public_key_string(self, ip, port):
        hashkey = self.hash_peer(ip, port)
        key = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        return AnonCrypto.pub_key_to_str(key)

    """ factory to return TCPHandler with a reference to the net instance, """
    """ thus it can emit a signal to GUI and call the appropriate net functions """
    def handler_factory(self):
        def create_handler(*args, **keys):
            return TCPHandler(self, *args, **keys)
        return create_handler

# handler for each TCP connection
class TCPHandler(SocketServer.BaseRequestHandler):
    """ One instance per connection. """
    def __init__(self, parent, *args, **keys):
        self.parent = parent
        SocketServer.BaseRequestHandler.__init__(self, *args, **keys)

    """ send data to correct function in Net class """
    def handle(self):
        data = AnonNet.recv_from_socket(self.request)
        (function, msg) = marshal.loads(data)
        if function == "invite":
            self.parent.recv_invite(msg)
        elif function == "accept":
            self.parent.inform_phase(msg)
        elif function == "inform":
            self.parent.recv_voucher(msg)
        elif function == "quit":
            self.parent.recv_quit_voucher(msg)
        elif function == "expel":
            self.parent.recv_expel_voucher(msg)
        elif function == "interested?":
            self.parent.recv_interest_voucher(msg)
        elif function == "interested":
            self.parent.recv_interested(msg)
        elif function[:7] == "prepare":
            self.parent.recv_prepare(msg, function)
        else:
            self.parent.emit(SIGNAL("messageReceived(QString)"), QString("not sure what to do with: " + str(function)))

# threaded server for receiving messages
class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

class DelayTimer(threading.Thread):
    def __init__(self, minutes, action):
        self.minutes = minutes
        self.action = action
        threading.Thread.__init__(self)
    
    def run(self):
        time.sleep(60*self.minutes)
        self.action()
