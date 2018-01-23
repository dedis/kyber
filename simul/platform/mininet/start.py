#!/usr/bin/python

"""
This will run a number of hosts on the server and do all
the routing to being able to connect to the other mininets.

You have to give it a list of server/net/nbr for each server
that has mininet installed and what subnet should be run
on it.

It will create nbr+1 entries for each net, where the ".1" is the
router for the net, and ".2"..".nbr+1" will be the nodes.
"""

from __future__ import print_function
import sys, time, threading, os, datetime, contextlib, errno, platform, shutil
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, setLogLevel
from mininet.node import Node, Host, OVSController
from mininet.util import netParse, ipAdd, irange
from mininet.nodelib import NAT
from mininet.link import TCLink
from subprocess import Popen, PIPE, call
from mininet.node import OVSController

# What debugging-level to use
debugLvl = 1
# Debug-string for color and time
debugStr = ""
# Logging-file
logfile = "/tmp/mininet.log"
logdone = "/tmp/done.log"
# Whether a ssh-daemon should be launched
runSSHD = False
# The port used for socat
socatPort = 5000
# Socat formats
# socatSend = "tcp4"
# socatRcv = "tcp4-listen"
socatSend = "udp-sendto"
socatRcv = "udp4-listen"
# Whether to redirect all socats to the main-gateway at 10.1.0.1
socatDirect = True
# If we want to end up in the CLI
startCLI = False

def dbg(lvl, *str):
    if lvl <= debugLvl:
        print("start.py:", end=" ")
        for s in str:
            print(s, end=" ")
        print()
        sys.stdout.flush()

class BaseRouter(Node):
    """"A Node with IP forwarding enabled."""
    def config( self, rootLog=None, **params ):
        super(BaseRouter, self).config(**params)
        dbg( 2, "Starting router %s at %s" %( self.IP(), rootLog) )
        for (gw, n, i) in otherNets:
            dbg( 3, "Adding route for", n, gw )
            self.cmd( 'route add -net %s gw %s' % (n, gw) )
        if runSSHD:
            self.cmd('/usr/sbin/sshd -D &')

        self.cmd( 'sysctl net.ipv4.ip_forward=1' )
        self.cmd( 'iptables -t nat -I POSTROUTING -j MASQUERADE' )
        socat = "socat OPEN:%s,creat,append %s:%d,reuseaddr,fork" % (logfile, socatRcv, socatPort)
        self.cmd( '%s &' % socat )
        if rootLog:
            self.cmd('tail -f %s | socat - %s:%s:%d &' % (logfile, socatSend, rootLog, socatPort))

    def terminate( self ):
        dbg( 2, "Stopping router" )
        for (gw, n, i) in otherNets:
            dbg( 3, "Deleting route for", n, gw )
            self.cmd( 'route del -net %s gw %s' % (n, gw) )

        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        self.cmd( 'killall socat' )
        self.cmd( 'iptables -t nat -D POSTROUTING -j MASQUERADE' )
        super(BaseRouter, self).terminate()


class Conode(Host):
    """A conode running in a host"""
    def config(self, gw=None, simul="", rootLog=None, **params):
        self.gw = gw
        self.simul = simul
        self.rootLog = rootLog
        super(Conode, self).config(**params)
        if runSSHD:
            self.cmd('/usr/sbin/sshd -D &')

    def startConode(self):
        if self.rootLog and socatDirect:
            socat="socat - %s:%s:%d" % (socatSend, self.rootLog, socatPort)
        else:
            socat="socat - %s:%s:%d" % (socatSend, self.gw, socatPort)

        args = "-debug %s -address %s:2000 -simul %s" % (debugLvl, self.IP(), self.simul)
        if True:
            args += " -monitor %s:10000" % global_root
        ldone = ""
        # When the first conode on a physical server ends, tell `start.py`
        # to go on. ".0.1" is the BaseRouter.
        if self.IP().endswith(".0.2"):
            ldone = "; date > " + logdone
        dbg( 3, "Starting conode on node", self.IP(), args, ldone, socat )
        self.cmd('( %s ./conode %s 2>&1 %s ) | %s &' %
                     (debugStr, args, ldone, socat ))

    def terminate(self):
        dbg( 3, "Stopping conode" )
        self.cmd('killall socat conode')
        super(Conode, self).terminate()


class InternetTopo(Topo):
        """Create one switch with all hosts connected to it and host
        .1 as router - all in subnet 10.x.0.0/16"""
        def __init__(self, myNet=None, rootLog=None, **opts):
            Topo.__init__(self, **opts)
            server, mn, n = myNet[0]
            switch = self.addSwitch('s0')
            baseIp, prefix = netParse(mn)
            gw = ipAdd(1, prefix, baseIp)
            dbg( 2, "Gw", gw, "baseIp", baseIp, prefix,
                 "Bandwidth:", bandwidth, "- delay:", delay)
            hostgw = self.addNode('h0', cls=BaseRouter,
                                  ip='%s/%d' % (gw, prefix),
                                  inNamespace=False,
                                  rootLog=rootLog)
            self.addLink(switch, hostgw)

            for i in range(1, int(n) + 1):
                ipStr = ipAdd(i + 1, prefix, baseIp)
                host = self.addHost('h%d' % i, cls=Conode,
                                    ip = '%s/%d' % (ipStr, prefix),
                                    defaultRoute='via %s' % gw,
			                	    simul=simulation, gw=gw,
                                    rootLog=rootLog)
                dbg( 3, "Adding link", host, switch )
                self.addLink(host, switch, bw=bandwidth, delay=delay)

def RunNet():
    """RunNet will start the mininet and add the routes to the other
    mininet-services"""
    rootLog = None
    if myNet[1] > 0:
        i, p = netParse(otherNets[0][1])
        rootLog = ipAdd(1, p, i)
    dbg( 2, "Creating network", myNet )
    topo = InternetTopo(myNet=myNet, rootLog=rootLog)
    dbg( 3, "Starting on", myNet )

    net = Mininet(topo=topo, link=TCLink, controller = OVSController)
    net.start()

    for host in net.hosts[1:]:
        host.startConode()

    # Also set setLogLevel('info') if you want to use this, else
    # there is no correct reporting on commands.
    if startCLI:
        CLI(net)
    log = open(logfile, "r")
    while not os.path.exists(logdone):
        dbg( 4, "Waiting for conode to finish at " + platform.node() )
        try:
            print(log.read(), end="")
            sys.stdout.flush()
        except IOError:
            time.sleep(1)

        time.sleep(1)

    # Write last line of log
    print(log.read(), end="")
    sys.stdout.flush()
    log.close()

    dbg( 2, "conode is finished %s" % myNet )
    net.stop()

def GetNetworks(filename):
    """GetServer reads the file and parses the data according to
    server, net, count
    It returns the first server encountered, our network if our ip is found
    in the list and the other networks."""

    global simulation, bandwidth, delay, socatDirect, debugLvl, debugStr, preScript

    process = Popen(["ip", "a"], stdout=PIPE)
    (ips, err) = process.communicate()
    process.wait()

    with open(filename) as f:
        content = f.readlines()

    # Interpret the first two lines of the file with regard to the
    # simulation to run
    simulation, bw, d = content.pop(0).rstrip().split(' ')
    bandwidth = int(bw)
    delay = d + "ms"
    dbgLvl, dbgTime, dbgColor = content.pop(0).rstrip().split(' ')
    debugLvl = int(dbgLvl)
    if dbgTime == "true":
        debugStr = "DEBUG_TIME=true "
    if dbgColor == "true":
        debugStr += "DEBUG_COLOR=true"
    preScript = content.pop(0).rstrip().split(' ')[0]

    list = []
    for line in content:
        list.append(line.rstrip().split(' '))

    otherNets = []
    myNet = None
    pos = 0
    totalHosts = 0
    for (server, net, count) in list:
        totalHosts += int(count)
        t = [server, net, count]
        if ips.find('inet %s/' % server) >= 0:
            myNet = [t, pos]
        else:
            otherNets.append(t)
        pos += 1

    if totalHosts > 2000:
        dbg(0, "Redirection output through local gateway")
        socatDirect = False

    if preScript != "":
        dbg(0, "Running PreScript " + preScript)
        call("./%s mininet" % preScript, shell=True)

    return list[0][0], myNet, otherNets


def rm_file(file):
    try:
        os.remove(file)
    except OSError:
        pass


def call_other(server, list_file):
    dbg( 3, "Calling remote server with", server, list_file )
    call("ssh -q %s sudo python -u start.py %s" % (server, list_file), shell=True)
    dbg( 3, "Done with start.py" )

# The only argument given to the script is the server-list. Everything
# else will be read from that and searched in the computer-configuration.
if __name__ == '__main__':
    if startCLI:
        setLogLevel('info')
    else:
        # With this loglevel CLI(net) does not report correctly.
        lg.setLogLevel( 'critical')
    if len(sys.argv) < 2:
        dbg(0, "please give list-name")
        sys.exit(-1)

    list_file = sys.argv[1]
    global_root, myNet, otherNets = GetNetworks(list_file)

    if myNet:
        dbg( 2, "Cleaning up mininet and logfiles" )
        # rm_file(logfile)
        rm_file(logdone)
        call("mn -c > /dev/null 2>&1", shell=True)

    threads = []
    if len(sys.argv) > 2:
        if len(otherNets) > 0:
            dbg( 2, "Starting remotely on nets", otherNets)
        for (server, mn, nbr) in otherNets:
            dbg( 3, "Cleaning up", server )
            call("ssh -q %s 'mn -c; pkill -9 -f start.py' > /dev/null 2>&1" % server, shell=True)
            dbg( 3, "Going to copy things %s to %s and run %s hosts in net %s" % \
                  (list_file, server, nbr, mn) )
            shutil.rmtree('config', ignore_errors=True)
            call("scp -q * %s %s:" % (list_file, server), shell=True)
            threads.append(threading.Thread(target=call_other, args=[server, list_file]))

        time.sleep(1)
        for thr in threads:
            dbg( 3, "Starting thread", thr )
            thr.start()

    if myNet:
        dbg( 1, "Starting mininet for %s" % myNet )
        t1 = threading.Thread(target=RunNet)
        t1.start()
        time.sleep(1)
        t1.join()

    for thr in threads:
        thr.join()

    dbg( 2, "Done with main in %s" % platform.node())
