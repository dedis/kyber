package ibe

/*

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
)

type Ciphertext struct {
	// Random point rP
	U kyber.Point
	// Sigma attached to ID: sigma XOR H(rG_id)
	V []byte
	// ciphertext of the message M XOR H(sigma)
	W []byte
}

// H2Tag is the domain separation tag for the H2 hash function
func H2Tag() []byte {
	return []byte("IBE-H2")
}

// H3Tag is the domain separation tag for the H3 hash function
func H3Tag() []byte {
	return []byte("IBE-H3")
}

// H4Tag is the domain separation tag for the H4 hash function
func H4Tag() []byte {
	return []byte("IBE-H4")
}

// EncryptCCAonG1 implements the CCA identity-based encryption scheme from
// https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf for more information
// about the scheme.
// - master is the master key on G1
// - "identities" (rounds) are on G2
// - the Ciphertext.U point will be on G1
// - ID is the ID towards which we encrypt the message
// - msg is the actual message
// - seed is the random seed to generate the random element (sigma) of the encryption
// The suite must produce points which implements the `HashablePoint` interface.
func EncryptCCAonG1(s pairing.Suite, master kyber.Point, ID, msg []byte) (*Ciphertext, error) {
	if len(msg) > s.Hash().Size() {
		return nil, errors.New("plaintext too long for the hash function provided")
	}

	// 1. Compute Gid = e(master,Q_id)
	hG2, ok := s.G2().Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement `kyber.HashablePoint`")
	}
	Qid := hG2.Hash(ID)
	Gid := s.Pair(master, Qid)

	// 2. Derive random sigma
	sigma := make([]byte, len(msg))
	if _, err := rand.Read(sigma); err != nil {
		return nil, fmt.Errorf("err reading rand sigma: %v", err)
	}
	// 3. Derive r from sigma and msg
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	// 4. Compute U = rP
	U := s.G1().Point().Mul(r, s.G1().Point().Base())

	// 5. Compute V = sigma XOR H2(rGid)
	rGid := Gid.Mul(r, Gid) // even in Gt, it's additive notation
	hrGid, err := gtToHash(s, rGid, len(msg))
	if err != nil {
		return nil, err
	}
	V := xor(sigma, hrGid)

	// 6. Compute M XOR H(sigma)
	hsigma, err := h4(s, sigma, len(msg))
	if err != nil {
		return nil, err
	}
	W := xor(msg, hsigma)

	return &Ciphertext{
		U: U,
		V: V,
		W: W,
	}, nil
}

// DecryptCCAonG1 decrypts ciphertexts encrypted using EncryptCCAonG1 given a G2 "private" point
func DecryptCCAonG1(s pairing.Suite, private kyber.Point, c *Ciphertext) ([]byte, error) {
	if len(c.W) > s.Hash().Size() {
		return nil, errors.New("ciphertext too long for the hash function provided")
	}

	// 1. Compute sigma = V XOR H2(e(rP,private))
	rGid := s.Pair(c.U, private)
	hrGid, err := gtToHash(s, rGid, len(c.W))
	if err != nil {
		return nil, err
	}
	if len(hrGid) != len(c.V) {
		return nil, fmt.Errorf("XorSigma is of invalid length: exp %d vs got %d", len(hrGid), len(c.V))
	}
	sigma := xor(hrGid, c.V)

	// 2. Compute M = W XOR H4(sigma)
	hsigma, err := h4(s, sigma, len(c.W))
	if err != nil {
		return nil, err
	}

	msg := xor(hsigma, c.W)

	// 3. Check U = rP
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	rP := s.G1().Point().Mul(r, s.G1().Point().Base())
	if !rP.Equal(c.U) {
		return nil, fmt.Errorf("invalid proof: rP check failed")
	}
	return msg, nil
}

// EncryptCCAonG2 implements the CCA identity-based encryption scheme from
// https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf for more information
// about the scheme.
// - master is the master key on G2
// - identities ("round") are on G1
// - the Ciphertext.U point will be on G2
// - ID is the ID towards which we encrypt the message
// - msg is the actual message
// - seed is the random seed to generate the random element (sigma) of the encryption
// The suite must produce points which implements the `HashablePoint` interface.
func EncryptCCAonG2(s pairing.Suite, master kyber.Point, ID, msg []byte) (*Ciphertext, error) {
	if len(msg) > s.Hash().Size() {
		return nil, errors.New("plaintext too long for the hash function provided")
	}

	// 1. Compute Gid = e(Q_id, master)
	hG2, ok := s.G1().Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement `kyber.HashablePoint`")
	}
	Qid := hG2.Hash(ID)
	Gid := s.Pair(Qid, master)

	// 2. Derive random sigma
	sigma := make([]byte, len(msg))
	if _, err := rand.Read(sigma); err != nil {
		return nil, fmt.Errorf("err reading rand sigma: %v", err)
	}
	// 3. Derive r from sigma and msg
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	// 4. Compute U = rP
	U := s.G2().Point().Mul(r, s.G2().Point().Base())

	// 5. Compute V = sigma XOR H2(rGid)
	rGid := Gid.Mul(r, Gid) // even in Gt, it's additive notation
	hrGid, err := gtToHash(s, rGid, len(msg))
	if err != nil {
		return nil, err
	}
	V := xor(sigma, hrGid)

	// 6. Compute M XOR H(sigma)
	hsigma, err := h4(s, sigma, len(msg))
	if err != nil {
		return nil, err
	}
	W := xor(msg, hsigma)

	return &Ciphertext{
		U: U,
		V: V,
		W: W,
	}, nil
}

// DecryptCCAonG2 decrypts ciphertexts encrypted using EncryptCCAonG2 given a G1 "private" point
func DecryptCCAonG2(s pairing.Suite, private kyber.Point, c *Ciphertext) ([]byte, error) {
	if len(c.W) > s.Hash().Size() {
		return nil, errors.New("ciphertext too long for the hash function provided")
	}

	// 1. Compute sigma = V XOR H2(e(rP,private))
	rGid := s.Pair(private, c.U)
	hrGid, err := gtToHash(s, rGid, len(c.W))
	if err != nil {
		return nil, err
	}
	if len(hrGid) != len(c.V) {
		return nil, fmt.Errorf("XorSigma is of invalid length: exp %d vs got %d", len(hrGid), len(c.V))
	}
	sigma := xor(hrGid, c.V)

	// 2. Compute M = W XOR H4(sigma)
	hsigma, err := h4(s, sigma, len(c.W))
	if err != nil {
		return nil, err
	}

	msg := xor(hsigma, c.W)

	// 3. Check U = rP
	r, err := h3(s, sigma, msg)
	if err != nil {
		return nil, err
	}
	rP := s.G2().Point().Mul(r, s.G2().Point().Base())
	if !rP.Equal(c.U) {
		return nil, fmt.Errorf("invalid proof: rP check failed")
	}
	return msg, nil
}

// hash sigma and msg to get r
func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
	h := s.Hash()

	if _, err := h.Write(H3Tag()); err != nil {
		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
	}
	if _, err := h.Write(sigma); err != nil {
		return nil, fmt.Errorf("err hashing sigma: %v", err)
	}
	_, _ = h.Write(msg)
	// we hash it a first time: buffer = hash("IBE-H3" || sigma || msg)
	buffer := h.Sum(nil)

	hashable, ok := s.G1().Scalar().(*mod.Int)
	if !ok {
		return nil, fmt.Errorf("unable to instantiate scalar as a mod.Int")
	}
	canonicalBitLen := hashable.MarshalSize() * 8
	actualBitLen := hashable.M.BitLen()
	toMask := canonicalBitLen - actualBitLen

	for i := uint16(1); i < 65535; i++ {
		h.Reset()
		// We will hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
		// value that is suitable as a scalar.
		iter := make([]byte, 2)
		binary.LittleEndian.PutUint16(iter, i)
		_, _ = h.Write(iter)
		_, _ = h.Write(buffer)
		hashed := h.Sum(nil)
		// We then apply masking to our resulting bytes at the bit level
		// but we assume that toMask is a few bits, at most 8.
		// For instance when using BLS12-381 toMask == 1.
		if hashable.BO == mod.BigEndian {
			hashed[0] = hashed[0] >> toMask
		} else {
			hashed[len(hashed)-1] = hashed[len(hashed)-1] >> toMask
		}
		// NOTE: Here we unmarshal as a test if the buffer is within the modulo
		// because we know unmarshal does this test. This implementation
		// is almost generic if not for this line. TO make it truly generic
		// we would need to add methods to create a scalar from bytes without
		// reduction and a method to check if it is within the modulo on the
		// Scalar interface.
		if err := hashable.UnmarshalBinary(hashed); err == nil {
			return hashable, nil
		}
	}
	// if we didn't return in the for loop then something is wrong
	return nil, fmt.Errorf("rejection sampling failure")
}

func h4(s pairing.Suite, sigma []byte, length int) ([]byte, error) {
	h4 := s.Hash()

	if _, err := h4.Write(H4Tag()); err != nil {
		return nil, fmt.Errorf("err writing h4tag: %v", err)
	}
	if _, err := h4.Write(sigma); err != nil {
		return nil, fmt.Errorf("err writing sigma to h4: %v", err)
	}
	h4sigma := h4.Sum(nil)[:length]

	return h4sigma, nil
}

func gtToHash(s pairing.Suite, gt kyber.Point, length int) ([]byte, error) {
	hash := s.Hash()

	if _, err := hash.Write(H2Tag()); err != nil {
		return nil, errors.New("err writing dst to gtHash")
	}
	if _, err := gt.MarshalTo(hash); err != nil {
		return nil, errors.New("err marshalling gt to the hash function")
	}

	hashReader := bytes.NewReader(hash.Sum(nil))
	var b = make([]byte, length)
	if _, err := hashReader.Read(b); err != nil {
		return nil, errors.New("couldn't read from hash output")
	}
	return b[:], nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("wrong xor input")
	}
	res := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = a[i] ^ b[i]
	}
	return res
}

type CiphertextCPA struct {
	// commitment
	RP kyber.Point
	// ciphertext
	C []byte
}

// EncryptCPAonG1 implements the CPA identity-based encryption scheme from
// https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf for more information
// about the scheme.
// SigGroup = G2 (large secret identities)
// KeyGroup = G1 (short master public keys)
// P random generator of G1
// dist master key: s, Ppub = s*P \in G1
// H1: {0,1}^n -> G1
// H2: GT -> {0,1}^n
// ID: Qid = H1(ID) = xP \in G2
//
//	secret did = s*Qid \in G2
//
// Encrypt:
//   - random r scalar
//   - Gid = e(Ppub, r*Qid) == e(P, P)^(x*s*r) \in GT
//     = GidT
//   - U = rP \in G1,
//   - V = M XOR H2(Gid)) = M XOR H2(GidT)  \in {0,1}^n
func EncryptCPAonG1(s pairing.Suite, basePoint, public kyber.Point, ID, msg []byte) (*CiphertextCPA, error) {
	if len(msg)>>16 > 0 {
		// we're using blake2 as XOF which only outputs 2^16-1 length
		return nil, errors.New("ciphertext too long")
	}
	hashable, ok := s.G2().Point().(kyber.HashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	Qid := hashable.Hash(ID)
	r := s.G2().Scalar().Pick(random.New())
	rP := s.G1().Point().Mul(r, basePoint)

	// e(Qid, Ppub) = e( H(round), s*P) where s is dist secret key
	Ppub := public
	rQid := s.G2().Point().Mul(r, Qid)
	GidT := s.Pair(Ppub, rQid)
	// H(gid)
	hGidT, err := gtToHash(s, GidT, len(msg))
	if err != nil {
		return nil, err
	}
	xored := xor(msg, hGidT)

	return &CiphertextCPA{
		RP: rP,
		C:  xored,
	}, nil
}

// DecryptCPAonG1 implements the CPA identity-based encryption scheme from
// https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf for more information
// about the scheme.
// SigGroup = G2 (large secret identities)
// KeyGroup = G1 (short master public keys)
// Decrypt:
//   - V XOR H2(e(U, did)) = V XOR H2(e(rP, s*Qid))
//     = V XOR H2(e(P, P)^(r*s*x))
//     = V XOR H2(GidT) = M
func DecryptCPAonG1(s pairing.Suite, private kyber.Point, c *CiphertextCPA) ([]byte, error) {
	GidT := s.Pair(c.RP, private)
	hGidT, err := gtToHash(s, GidT, len(c.C))

	if err != nil {
		return nil, err
	}
	return xor(c.C, hGidT), nil
}
*/
