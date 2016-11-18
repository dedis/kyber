#Implementation of padding scheme.
#Just needs to generate how much padding is needed
#and a function that returns the padded value
import math
#take log base 2
def log2(x):
    return math.log(x,2)
PADOVER = 0 # is this needed?
#Does not implement overhead for encryption as PURB.
def zeroBits(n):
#works for float and int, although possibly should have different functions
#for each anyways.
    msgBits = int(math.ceil(log2(int(math.ceil(n+PADOVER)+1)))) #msg bits
    leakBits = int(math.ceil(log2(msgBits)))#XXX +1 #+1 doesn't change assymptotic
#but should be examined more to see if it shouold be there (copied from go code)
    return msgBits - leakBits
def calcPad(x):
#    print x
    if x==0: return 0
    zeroB = zeroBits(x)
    msgBits = int(math.ceil(log2(int(math.ceil(x+PADOVER)+1)))) #msg bits
    needed = int(math.ceil(x))+PADOVER
    mask = 0
    for i in xrange(0, zeroB):
        mask |= (1 << i)
    #mask *=int(math.pow(2,zeroB))
#    print mask, zeroB
#    print bin(mask)
    needed &= mask
#    print bin(needed), needed
    needed = int(math.pow(2,zeroB)) -needed
#    print bin(needed),needed
    #needed = needed + 1
    total = needed+x+PADOVER
#    print "end result",bin(needed+x+PADOVER)
#    print "Needed + overhead",bin(needed+PADOVER)
#    print "input val",bin(x)

    return total

#Calculates padding required to pad to next power of 2
def pow2Pad(x):
    l = int(math.ceil(int(log2(x+PADOVER)+1)))
    pad = int(math.pow(2,l))-int(x)
#   print pad, x
    return pad+x

