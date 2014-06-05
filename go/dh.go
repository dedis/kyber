package main

import "strings"
import "math/big"
import "math/rand"

type Parameters struct {
  P, G *big.Int
}

type PublicKey struct {
  Parameters
  Y *big.Int
}

type PrivateKey struct {
  PublicKey
  X *big.Int
}

const (
  G = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F" +
      "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213" +
      "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1" +
      "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A" +
      "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24" +
      "855E6EEB 22B3B2E5"
  P = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6" +
      "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0" +
      "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70" +
      "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0" +
      "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708" +
      "DF1FB2BC 2E4A4371"
)

func GetParameters() *Parameters {
  params := new(Parameters)
  params.G, _ = new(big.Int).SetString(strings.Replace(G, " ", "", -1), 16)
  params.P, _ = new(big.Int).SetString(strings.Replace(P, " ", "", -1), 16)
  return params
}

func GeneratePrivateKey(params *Parameters) *PrivateKey {
  random := rand.New(rand.NewSource(rand.Int63()))
  x := new(big.Int).Rand(random, params.P)
  y := new(big.Int).Exp(params.G, x, params.P)
  return &PrivateKey{PublicKey{*params, y}, x}
}

func (pri *PrivateKey) Exchange(pub *PublicKey) *big.Int {
  return new(big.Int).Exp(pub.Y, pri.X, pub.P)
}

func main() {
  params := GetParameters()
  k0 := GeneratePrivateKey(params)
  k1 := GeneratePrivateKey(params)
  s0 := k0.Exchange(&k1.PublicKey)
  s1 := k1.Exchange(&k0.PublicKey)
  if s0.Cmp(s1) != 0 {
    panic("s0 != s1")
  }
}
