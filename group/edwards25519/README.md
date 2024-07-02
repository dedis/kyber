This implementation of ed25519 follows SUPERCOP ref10. The field elements are represented as follows: 

`t[0] + t[1] * 2^26 + t[2] * 2^51 + t[3] * 2^77 + ... + t[9] * 2^230`

The test vectors to in `fe_test.go` were generated using this piece of code:

```
#!/usr/bin/env sage

import sage.all as sg

p = 2**255 -19
F = sg.GF(p)

base = [1, 2**26, 2**51, 2**77, 2**102, 2**128, 2**153, 2**179, 2**204, 2**230]
vectors = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        [1, -1, 1, -1, 1, -1, 1, -1, 1, -1],
        [123312, 54,36467,64465,23524,235,234532,643,8975,74654],
        [12323312, -54,356477,-69965,-23538, 32235, -233492,-643, 348975, 9174654],
]

for vect in vectors:
    res = F(0)
    i = 0
    for elem in vect:
        res += F(elem * base[i])
        i += 1

    print(res)
```

