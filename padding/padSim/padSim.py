#from scapy.all import *
import scapy
from scapy.all import *

#Not sure if this adds anything useful atm.
#from scapy_ssl_tls.ssl_tls import *
import sys
import math

import padding
import leak
#class pairs(a,b):
#bandwidth used for constant pading(not realalistic, currently chosen randomly)
#100 KB a second
BW = 102400
def filter_test():
    pkts = rdpcap(sys.argv[1])
    #ls(pkts)
    #ls(pkts[3])
    #print "read pcap"
    pkts = pkts.filter(lambda x: TCP in x)
    #pkts.summary()
    s = pkts.sessions()
    tmp ="dummy string"
    bidir = dict()
    #bidir[tmp] = (s[s.keys()[0]],0)
    cnt1 = 0
    cnt2 = 0

    for st, pk in s.iteritems():
        #create reversed string
     #   print st
        sp = st.split()
        if len(sp) < 4:
            continue
        stp = sp[0] +" " + sp[3] + " " + sp[2] + " " + sp[1]
      #  print stp
       # print "\n---------------------------------------\n"

        if stp in bidir:
            tmp = bidir[stp][0]
            bidir[stp]= (tmp,pk)
            cnt1 = cnt1+1
        else:
            bidir[st]=(pk,0)
            cnt2 = cnt2+1

    #for st in bidir:
     #   print st
   # print str(cnt1) + ":" + str(cnt2)

    #print "-------------------------------------------"
#if there are no TCP streams.
    if len(bidir.keys()) ==0:
        return
#solution to no block comment XXX Should be deleted eventually
    if 0==1:
        x = bidir.keys()[0]
        print x
        print bidir[x][0].show()

        if bidir[x][1] is not 0:
            print bidir[x][1].show()
        for st, pk in bidir.iteritems():
            print st
            print "----------- Sent packets -----------"
            totalPad=0
            total=0

            for p in pk[0]:
                t = p['TCP']
                l = len(t.payload)
                if l == 0: continue
                F = t.flags
                print F, bin(F), '\n'
                print t.time, l, padding.calcPad(l)
            print "----------- Recv packets -----------"
            if pk[1] is not 0:
                for p in pk[1]:
                    t = p['TCP']
                    l = len(t.payload)
                    if l == 0: continue
                    F = t.flags
                    print F, bin(F), '\n'
                    print t.time, l, padding.calcPad(l)
            else:
                print "No recieved packets"
                
    #Now run simulations
    for st, pk in bidir.iteritems():
        sent = bidir[st][0]
        recv = bidir[st][1]
        if len(sent) < 4: continue
        print st
        print "-----------------------------------------\nSent\n-----------------------------------------"
        purblSim(sent)
        pow2Sim(sent)
        print "-----------------------------------------\nRecv\n-----------------------------------------"
        if recv is not 0 and len(recv) < 2:
            purblSim(recv)
            pow2Sim(recv)
def purblSim(packets):
    print "\nPad using purbl padding scheme."
#total bytes sent originally
    total = 0
#Total bytes of padding
    totalP = 0
#Sum of overhead from padding
    ohPer = 0
#Number of packets
    numP = 0
    anonSet = 0
    for p in packets:
        t = p['TCP']
#ignore TCP packets without a payload
        if len(t.payload) == 0: continue
        total+=len(t.payload)
        numP += 1
        padded = padding.calcPad(len(t.payload))
        totalP+=padded
#Calculate the overhead of padding
        increase = padded - len(t.payload)
        overhead = float(increase)/(len(t.payload))
        ohPer+=overhead
#Print packet time, length of the TCP payload, length of the padded payload,
# and percent overhead
    #    print t.time, len(t.payload), padded, str(overhead*100)[0:4] + '% overhead'
        #Calculate anonymity sets:
        zeroBits = padding.zeroBits(int(len(t.payload)))
        aSetSize = leak.lenLeak(0,zeroBits)
        anonSet+=aSetSize
       # print "Size of anonymity set:", aSetSize
    #Get total time of communication
    connTime = packets[-1].time - packets[0].time
    if totalP ==0 or connTime == 0: return
    padTime = 0
    print "conn time: ", connTime
    if connTime!=0:
        padTime = padding.calcPad(int(math.ceil(connTime)))
        print "padded time:", padTime
    if connTime!=0:
        print "Time padding overhead:", str(float(padTime-connTime)/padTime*100)[0:4]+'%'
    print "total bytes:", total
    print "Total bytes with padding:", totalP
    print "Padding overhead:", str(float(totalP-total)/totalP*100)[0:4] + '%'
    print "Average overhead per packet:", str(ohPer/numP*100)[0:4] + '%'
    print "Anonymity set total (all msgs anonymity set added):", anonSet
    #pad connTime
    # convert from ms to s
#below should use padTime
    print "BW constant bit rate (B/s)", BW*(connTime/1000)
    print "BW constant bit rate with padding (B/s)", BW*(float(padTime)/1000)


def pow2Sim(packets):
    print "\nPad to nearest power of 2."
#total bytes sent originally
    total = 0
#Total bytes of padding
    totalP = 0
#Sum of overhead from padding
    ohPer = 0
#Number of packets
    numP = 0
    anonSet = 0
#Number of max length packets before this
#    maxPacket = 0
    for p in packets:
        t = p['TCP']
#ignore TCP packets without a payload
        if len(t.payload) == 0: continue
       # if len(t.payload) == MAXRECORD:
         #   maxPacket +=1
            #TODO Need to check if next packet exists.
            #TODO This solution doesn't work because not all TLS streams 
            #   will have the same max packet and it looks like applications increase 
            #   the size as it continues.
            #   Actual solution might be best to look at the dataset to see what
            #   assumptions make sense.
            #continue
        pLen = len(t.payload) #+ maxPacket*MAXRECORD
        total+= pLen
        numP += 1
        padded = padding.pow2Pad(pLen)
        totalP+=padded
#Calculate the overhead of padding
        increase = padded - pLen
        overhead = float(increase)/(pLen)
        ohPer+=overhead
#Print packet time, length of the TCP payload, length of the padded payload,
# and percent overhead
    #    print t.time, len(t.payload), padded, str(overhead*100)[0:4] + '% overhead'
        #Calculate anonymity sets:
        zeroBits = padding.zeroBits(int(pLen))
        aSetSize = leak.powLeak(math.ceil(math.log(pLen,2)))
        anonSet+=aSetSize
    #    print "Size of anonymity set:", aSetSize
    #Get total time of communication
    connTime = packets[-1].time - packets[0].time
    if totalP ==0 or connTime == 0: return
    padTime=0
    print "total payload bytes:", total
    print "Total bytes with padding:", totalP
    print "Padding overhead:", str(float(totalP-total)/totalP*100)[0:4] + '%'
    print "Average overhead per packet:", str(ohPer/numP*100)[0:4] + '%'
    print "Anonymity set total (all msgs anonymity set added):", anonSet
    #pad connTime
    # convert from ms to s
#below should use padTime
    print "conn time: ", connTime
    if connTime!=0:
        padTime = padding.pow2Pad(int(math.ceil(connTime)))
        print "padded time:", padTime
    if connTime!=0:
        print "Time padding overhead:", str(float(padTime-connTime)/padTime*100)[0:4]+'%'
    print "BW constant bit rate (B/s)", BW*(connTime/1000)
    print "BW constant bit rate with padding (B/s)", BW*(float(padTime)/1000)


filter_test()
