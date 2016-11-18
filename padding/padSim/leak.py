#File contains functions to determine how much information is leaked
import math
#will take the lengthBits, and how many of those bits are set to zero
#and calculate the number of possible messages
def lenLeak(lengthBits, zeroBits):
    return int(math.pow(2, zeroBits))
def powLeak(lengthBits):
    return int(math.pow(2, lengthBits)-math.pow(2,lengthBits-1))
