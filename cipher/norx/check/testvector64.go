/*
    testvector64.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package check

import norx "github.com/daeinar/norx-go/aead"
import "fmt"

func Testvector64() int {

    var klen uint64 = 32
    var nlen uint64 = 16
    var hlen uint64 = 16
    var mlen uint64 = 32
    var tlen uint64 = 0
    var clen uint64 = 32 + 32

    k := make ([]uint8, klen)
    n := make ([]uint8, nlen)
    h := make ([]uint8, hlen)
    m := make ([]uint8, mlen)
    t := make ([]uint8, tlen)
    c := make ([]uint8, clen)

    clen = 0

    norx.STORE64(k[ 0: 8], uint64(0x0011223344556677))
    norx.STORE64(k[ 8:16], uint64(0x8899AABBCCDDEEFF))
    norx.STORE64(k[16:24], uint64(0xFFEEDDCCBBAA9988))
    norx.STORE64(k[24:32], uint64(0x7766554433221100))

    norx.STORE64(n[ 0: 8], uint64(0xFFFFFFFFFFFFFFFF))
    norx.STORE64(n[ 8:16], uint64(0xFFFFFFFFFFFFFFFF))

    norx.STORE64(h[ 0: 8], uint64(0x1000000000000002))
    norx.STORE64(h[ 8:16], uint64(0x3000000000000004))

    norx.STORE64(m[ 0: 8], uint64(0x8000000000000007))
    norx.STORE64(m[ 8:16], uint64(0x6000000000000005))
    norx.STORE64(m[16:24], uint64(0x4000000000000003))
    norx.STORE64(m[24:32], uint64(0x2000000000000001))

    norx.AEAD_encrypt(c, &clen, h, hlen, m, mlen, t, tlen, n, k)

    fmt.Printf("C: %016X %016X %016X %016X\n", norx.LOAD64(c[ 0: 8]), norx.LOAD64(c[ 8:16]), norx.LOAD64(c[16:24]), norx.LOAD64(c[24:32]))
    fmt.Printf("A: %016X %016X %016X %016X\n", norx.LOAD64(c[32:40]), norx.LOAD64(c[40:48]), norx.LOAD64(c[48:56]), norx.LOAD64(c[56:64]))

    return 0
}
