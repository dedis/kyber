#!/usr/bin/env python

import binascii
import random

from Crypto.Util.number import bytes_to_long

def _s2l(s):
    s = bytes("".join(s.split()), "UTF-8")
    s = binascii.a2b_hex(s)
    return bytes_to_long(s)

class DiffieHellman:
    g = _s2l("A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F"
        "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213"
        "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1"
        "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A"
        "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24"
        "855E6EEB 22B3B2E5")
    p = _s2l("B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6"
        "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0"
        "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70"
        "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0"
        "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708"
        "DF1FB2BC 2E4A4371")

    def __init__(self):
        self.x = random.randrange(1 << (self.q.bit_length() - 1), self.q - 1)
        self.y = pow(self.g, self.x, self.p)

    def exchange(self, other_y):
        return pow(other_y, self.x, self.p)

def main():
    dh0 = DiffieHellman()
    dh1 = DiffieHellman()

    assert dh0.exchange(dh1.y) == dh1.exchange(dh0.y)

if __name__ == "__main__":
    main()
