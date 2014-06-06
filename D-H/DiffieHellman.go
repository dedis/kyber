package main

import (
    "fmt"
    "math"
    "crypto"
    "encoding/binary"
    "math/big"
    _ "crypto/sha256"
)

// Generates a fresh prime for two parties to share
func getBase() *big.Int {
    base := big.NewInt(961748941)
    return base // random number
}

// Generates fresh base for two parties to share
func getPrime() *big.Int {
    return big.NewInt(13)
}

// Calculates public component = base ^ secret % prime
func getPublicKey(base, secret, prime *big.Int) *big.Int {
    return new(big.Int).Exp(base, secret, prime)
}

// UTILITY: hashes data and converts it into a big integer, using sha256
func hashThis(data *big.Int) *big.Int {
    hash := crypto.SHA256.New()
    hash.Write(data.Bytes())
    newhash := binary.LittleEndian.Uint32(hash.Sum(nil))
    fmt.Println(data, "hash sum", hash.Sum(nil), newhash)
    return big.NewInt(int64(newhash))
}

// UTILITY: converts big int to a float64
func toF (i *big.Int) float64 {
    return float64(i.Int64())
}

// UTILITY: converts big int to uint
func toU (i *big.Int) uint {
    return uint(i.Uint64())
}

// UTILITY: takes in array of big ints and applies left shifts to them
func lshM(buf []*big.Int) *big.Int {

}

// Interface (can be used by other programs)
type DiffieHellman interface {
    getSharedSecret(*big.Int) *big.Int
    proveSharedSecret(*big.Int) (*big.Int, *big.Int, *big.Int)
    verifySharedSecret(*big.Int, *big.Int, *big.Int, *big.Int, *big.Int) int64
}

// @P: prime
// @G: base
type key struct {
    DiffieHellman
    secret, P, G, PublicKey *big.Int
    // capitalized letters are visible to other classes
}

// Get the shared secret of prover k and another key
func (k key) getSharedSecret(otherpub *big.Int) *big.Int {
    return big.NewInt(int64(math.Pow(toF(otherpub), toF(k.secret))))
}

func (k key) proveSharedSecret(remote_pub *big.Int) (*big.Int,  *big.Int,
    *big.Int) {
    newb := new(big.Int)
    phi := newb.Sub(k.P, big.NewInt(1))

    prover_pub := k.PublicKey
    secret := k.getSharedSecret(remote_pub)

    randomKey := key{secret: big.NewInt(3), P: k.P, G: k.G}
    // another element of group P_q
    commit1 := getPublicKey(k.G, big.NewInt(5), k.P)
    randomKey.PublicKey = commit1
    commit2 := randomKey.getSharedSecret(remote_pub)

    prechallenge := newb.Lsh(k.G, toU(prover_pub), secret, remote_pub, commit1,
        commit2)
    challenge := hashThis(prechallenge)

    // prover secret
    prod := newb.Rem(newb.Mul(k.secret, challenge), phi)
    response := newb.Rem(newb.Sub(randomKey.secret, prod), phi)

    return secret, challenge, response
}

func (k key) verifySharedSecret(prover_pub, other_pub, secret, challenge,
    response *big.Int) int64 {

    prime := (k.P).Int64()
    commit1p1 := int64(math.Pow(toF(k.G), toF(response))) % prime
    commit1p2 := int64(math.Pow(toF(k.PublicKey), toF(challenge))) % prime
    commit1 :=  commit1p1 * commit1p2

    commit2p1 := int64(math.Pow(toF(other_pub), toF(response))) % prime
    commit2p2 := int64(math.Pow(toF(secret), toF(challenge))) % prime
    commit2 :=  commit2p1 * commit2p2

    pre = []big.Int
    prenewhash := new(big.Int).Lsh(k.G, toU(prover_pub), other_pub, secret, commit1, commit2)
    newhash := hashThis(prenewhash)

    if challenge == newhash {
        return secret.Int64()
    } else {
        return -1
    }
}

// Test section
func main() {
    a := key {secret: big.NewInt(3)}
    a.P = getPrime()
    a.G = getBase()
    a.PublicKey = getPublicKey(a.G, a.secret, a.P)

    bpub := big.NewInt(int64(math.Pow(toF(a.G), 4.0)) % (a.P).Int64())
    secret, challenge, response := a.proveSharedSecret(bpub)
    final := a.verifySharedSecret(a.PublicKey, bpub, secret, challenge, response)
    fmt.Println("final", final)
}
