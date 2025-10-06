// Package implements TDH2, a threshold encryption scheme
// where decryption is secreted shared among n parties.
// Decryption requires a threshold of t+1 parties to cooperate.
// The scheme is based on ElGamal encryption and uses non-interactive
// zero-knowledge proofs (NIZK) to ensure the correctness of encryption
// See the original paper for more theoretical details:
// https://www.shoup.net/papers/thresh1.pdf by Victor Shoup and Rosario Gennaro
// This scheme is proven to be secure against chosen ciphertext attack
// (CCA secure) under the decisional Diffie-Hellman (DDH) assumption
//
// For this implementation, this specification is followed,
// https://github.com/coinbase/cb-mpc/blob/master/docs/spec/tdh2-spec.pdf
// Similar to the specification, this implementation also provides an
// alternative to the original one time-pad encryption of the message.
// If useAESGCM is set to true, AES-GCM (256-bit) is used instead of the one-time-pad.
// We also support labels that can be used as associated data in the AEAD scheme.
//
// TODO: in the future we might update this implemntation to benefit from
// improvemetns provided in the following paper:
// https://eprint.iacr.org/2025/1578.pdf
package tdh2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/util/random"
	"golang.org/x/crypto/sha3"
)

const (
	// minimum acceptable message size (lambda)
	ComputationalSecurityParameter = 128
	// length of supported AES key in bytes
	AESBytes = 32
	// length of AES-GCM nonce in bytes
	NonceSize = 12
)

// Suite is the interface that groups the necessary methods for this scheme
// TDH2 requires a cyclic group where the Decisional Diffie–Hellman (DDH) assumption holds
// Ideally an elliptic curve group G with generator g and with prime order q
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Random
}

// CipherText represents the ciphertext produced by the encryption scheme
// along with an embedded NIZK proof of correctness
type CipherText struct {
	W []byte // ciphertext (for aes_gcm, ciphertext is prepended with nonce)
	L []byte // optional label
	P int    // padding on the original message
	// Embedded NIZK (Chaum–Pedersen style)
	R1, R2 kyber.Point
	E, F   kyber.Scalar
}

// PartialDecryptionShare represents a partial decryption share produced by a
// party, along with an embedded NIZK proof of correctness
type PartialDecryptionShare struct {
	Index uint32
	Xi    kyber.Point
	// Embedded NIZK (Chaum–Pedersen style)
	Ei kyber.Scalar
	Fi kyber.Scalar
}

// Encrypt encrypts a message and returns the ciphertext
// label is optional, if no label is provided, use empty string
// if useAESGCM is true, AES-256-GCM (96 bits nonce size) is used instead of hashing the key and xoring
// as described in the original paper.
func Encrypt(
	suite Suite,
	pk kyber.Point,
	message []byte,
	label []byte,
	useAESGCM bool,
) (*CipherText, error) {
	// if no label is provided use empty string
	if label == nil {
		label = []byte("")
	}

	randomStream := suite.RandomStream()

	// generate a random scalar for ephemeral private key
	r := suite.Scalar().Pick(randomStream)
	s := suite.Scalar().Pick(randomStream)

	// ephemeral DH shared secret (ss = g^{r . pk})
	// where pk is the public key and r is a random scalar
	ss := suite.Point().Mul(r, pk)

	var w []byte
	var p int
	if useAESGCM { // if aes gcm is requested
		// generate random nonce for AES-GCM
		nonce := make([]byte, NonceSize)
		random.Bytes(nonce, randomStream)

		// hash the ephemeral shared secret and produce aes key
		aesKey, err := hash1(suite, ss, AESBytes)
		if err != nil {
			return nil, fmt.Errorf("h1 failed: %w", err)
		}

		// setup AES GCM
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		// apply encryption of the message given nonce and label as additional data
		c := aead.Seal(nil, nonce, message, label)

		// prepend nonce as part of cipher text
		w = append(nonce, c...)

	} else { // use default: one-time pad

		// pad message to at least ComputationalSecurityParameter bytes
		if len(message) < ComputationalSecurityParameter/8 {
			p = ComputationalSecurityParameter/8 - len(message)
			padding := make([]byte, p)
			message = append(message, padding...)
		}

		// apply hash and cut to the length of message
		hashed, err := hash1(suite, ss, len(message))
		if err != nil {
			return nil, fmt.Errorf("h1 failed: %w", err)
		}

		// H1(h^r) ⊕ m
		w, err = xorByteSlices(hashed, message)
		if err != nil {
			return nil, fmt.Errorf("xor failed: %w", err)
		}
	}

	r1 := suite.Point().Mul(r, nil) // r1 = r . G
	r2 := suite.Point().Mul(r, pk)  // r2 = r . pub

	w1 := suite.Point().Mul(s, nil) // w1 = s . G
	w2 := suite.Point().Mul(s, pk)  // w2 = s . pub

	e, err := hash2(suite, w, label, r1, w1, r2, w2)
	if err != nil {
		return nil, fmt.Errorf("cannot compute hash2: %w", err)
	}

	// f = s + r.e (mod q)
	f := suite.Scalar().Add(s, suite.Scalar().Mul(r, e.Clone()))

	return &CipherText{
		W:  w,
		L:  label,
		P:  p,
		R1: r1,
		R2: r2,
		E:  e,
		F:  f,
	}, nil
}

// Verify checks the validity of the ciphertext and its embedded NIZK proof
func Verify(
	suite Suite,
	ct *CipherText,
	pk kyber.Point,
	expectedLabel []byte,
) error {
	// check expected label
	if !bytes.Equal(ct.L, expectedLabel) {
		return errors.New("label does not match")
	}

	// check if the R1 and R2 points are valid points in the curve
	// and are in proper subgroup
	if err := validatePoint(suite, ct.R1); err != nil {
		return fmt.Errorf("invalid R1: %w", err)
	}
	if err := validatePoint(suite, ct.R2); err != nil {
		return fmt.Errorf("invalid R2: %w", err)
	}

	// w1 = f * G - e * R1;
	w1 := suite.Point().Sub(
		suite.Point().Mul(ct.F, nil),
		suite.Point().Mul(ct.E, ct.R1),
	)

	// w2 = f * pk - e * R2;
	w2 := suite.Point().Sub(
		suite.Point().Mul(ct.F, pk),
		suite.Point().Mul(ct.E, ct.R2),
	)

	e, err := hash2(suite, ct.W, ct.L, ct.R1, w1, ct.R2, w2)
	if err != nil {
		return fmt.Errorf("cannot compute hash2: %w", err)
	}
	if !e.Equal(ct.E) {
		return fmt.Errorf("Verify failed: e mismatch")
	}
	return nil
}

// PartialDecrypt computes a partial decryption share for the given ciphertext
// using the private key share (ski) corresponding to the index.
// It also verifies the validity of the ciphertext and its embedded NIZK proof
// before proceeding with the partial decryption.
func PartialDecrypt(
	suite Suite,
	ct *CipherText,
	index uint32, // index
	ski kyber.Scalar, // private key share i
	expectedLabel []byte,
	pk kyber.Point, // public key
) (*PartialDecryptionShare, error) {
	if err := Verify(suite, ct, pk, expectedLabel); err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// generate a random scalar for ephemeral private key
	si := suite.Scalar().Pick(suite.RandomStream())

	xi := suite.Point().Mul(ski, ct.R1) // X_i = sk_i * r1
	yi := suite.Point().Mul(si, ct.R1)  // y_i = s_i * r1
	zi := suite.Point().Mul(si, nil)    // z_i = s_i * G

	// compute hash4
	ei, err := hash4(suite, xi, yi, zi)
	if err != nil {
		return nil, fmt.Errorf("cannot compute hash4: %w", err)
	}

	// f_i = s_i + e_i * x_i (mod q)
	fi := suite.Scalar().Add(si, suite.Scalar().Mul(ski, ei.Clone()))

	return &PartialDecryptionShare{
		Index: index,
		Xi:    xi,
		Ei:    ei,
		Fi:    fi,
	}, nil
}

// VerifyPartialDecryptionShare verifies the validity of a given partial decryption share
// and its embedded NIZK proof, using the public key share (pki) corresponding to the index
// and the public key (pk).
func VerifyPartialDecryptionShare(
	suite Suite,
	ct *CipherText,
	partial *PartialDecryptionShare,
	pki kyber.Point, // public key of node i
) error {
	// check if Xi is a valid curve point
	if err := validatePoint(suite, partial.Xi); err != nil {
		return fmt.Errorf("invalid Xi: %w", err)
	}

	// y_i = f_i * u - e_i * u_i
	yi := suite.Point().Sub(
		suite.Point().Mul(partial.Fi, ct.R1),
		suite.Point().Mul(partial.Ei, partial.Xi),
	)

	// z_i = f_i * G - e_i * q_i
	zi := suite.Point().Sub(
		suite.Point().Mul(partial.Fi, nil),
		suite.Point().Mul(partial.Ei, pki),
	)

	expectedEi, err := hash4(suite, partial.Xi, yi, zi)
	if err != nil {
		return fmt.Errorf("cannot compute hash4: %w", err)
	}

	if !partial.Ei.Equal(expectedEi) {
		return fmt.Errorf("hash4 mismatch")
	}

	return nil
}

// CombinePartialDecryptionShares combines a set of valid partial decryption shares
// to recover the original message. It first verifies the validity of the ciphertext
// and each partial decryption share, then uses Lagrange interpolation in the exponent
// to reconstruct the shared secret, and finally uses this shared secret to decrypt
// the ciphertext. If useAESGCM is true, AES-GCM is used for decryption instead of
// the one-time-pad method described in the original paper.
// It returns the decrypted message, the number of valid partial decryptions used,
// and an error if any.
// comparing the number of valid partial decryptions to the passed partials
// can help detect invalid or malicious shares.
func CombinePartialDecryptionShares(
	suite Suite,
	ct *CipherText,
	partials []*PartialDecryptionShare,
	publicKeys []kyber.Point, // order matters
	threshold int,
	expectedLabel []byte,
	pk kyber.Point, // public key
	useAESGCM bool,
) (msg []byte, validPartials int, err error) {
	// verify ciphertext
	if err := Verify(suite, ct, pk, expectedLabel); err != nil {
		return nil, 0, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// verify partials
	shares := make([]*share.PubShare, 0)
	for i := 0; i < len(partials); i++ {

		// fetch public key
		idx := partials[i].Index
		if int(idx) >= len(publicKeys) {
			return nil, 0, fmt.Errorf("invalid index")
		}
		qi := publicKeys[idx]

		if err := VerifyPartialDecryptionShare(suite, ct, partials[i], qi); err != nil {
			// skip the partial share
			continue
		}
		shares = append(shares, &share.PubShare{I: idx, V: partials[i].Xi})
	}

	// quorum check
	if len(shares) < threshold {
		return nil, 0, fmt.Errorf("not enough valid partial decryptions")
	}

	// Recover the shared secret (Lagrange interpolation in the exponent)
	v, err := share.RecoverCommit(suite, shares, threshold, len(publicKeys))
	if err != nil {
		return nil, 0, err
	}

	// message recovery step
	if useAESGCM {

		// decrypt the ciphertext using AES-GCM
		aesKey, err := hash1(suite, v, AESBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("h1 failed: %w", err)
		}

		// split w into Nonce and c
		if len(ct.W) < NonceSize {
			return nil, 0, fmt.Errorf("ct.w too short")
		}
		nonce, c := ct.W[:NonceSize], ct.W[NonceSize:]

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, 0, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, 0, err
		}
		plaintext, err := aead.Open(nil, nonce, c, expectedLabel)
		if err != nil {
			return nil, 0, err
		}
		return plaintext, len(shares), nil
	}

	// else
	hashed, err := hash1(suite, v, len(ct.W))
	if err != nil {
		return nil, 0, fmt.Errorf("h1 failed: %w", err)
	}

	message, err := xorByteSlices(hashed, ct.W)
	if err != nil {
		return nil, 0, fmt.Errorf("xor failed: %w", err)
	}
	// strip out the extra padding
	return message[:len(message)-ct.P], len(shares), nil
}

// h1Tag is the domain separation tag for the hash1 function
func h1Tag() []byte {
	return []byte("TDH2-H1")
}

// hash1 as described in the paper computes H1(point) -> string (cut to length)
// and returns the first 'length' bytes of the hash output
func hash1(suite Suite, point kyber.Point, length int) ([]byte, error) {
	hash := suite.Hash()
	if _, err := hash.Write(h1Tag()); err != nil {
		return nil, errors.New("err writing tag to hash")
	}

	// add group name to hash
	if err := addGroupToHash(hash, suite); err != nil {
		return nil, errors.New("err adding group to the hash function")
	}

	// add point encoding size
	if err := addPointToHash(hash, point); err != nil {
		return nil, errors.New("err adding point to the hash function")
	}

	hashSum := hash.Sum(nil)
	hashReader := bytes.NewReader(hashSum)

	// truncate
	if len(hashSum) >= length {
		var hashed = make([]byte, length)
		if _, err := hashReader.Read(hashed); err != nil {
			return nil, errors.New("couldn't read from hash output")
		}
		return hashed, nil
	}

	// else extend using sha3 SHAKE256 as XOF(extendable-output function)
	// TODO: we might want to use the random package in utils
	hasher := sha3.NewShake256()

	// seed the new hasher
	hasher.Write(hashSum)
	hashed := make([]byte, length)
	_, err := hasher.Read(hashed)
	if err != nil {
		return nil, errors.New("couldn't read from shake256 output")
	}
	return hashed, nil
}

// h2Tag is the domain separation tag for the hash2 function
func h2Tag() []byte {
	return []byte("TDH2-H2")
}

// hash2 as described in the paper computes hash2(ciphertext, label, r1, w1, r2, w2) -> scalar
func hash2(
	suite Suite,
	w, l []byte,
	r1, w1, r2, w2 kyber.Point,
) (kyber.Scalar, error) {

	hash := suite.Hash()
	if _, err := hash.Write(h2Tag()); err != nil {
		return nil, errors.New("err writing tag to hash")
	}

	if err := addGroupToHash(hash, suite); err != nil {
		return nil, errors.New("err adding group to the hash function")
	}

	if err := addStringToHash(hash, w); err != nil {
		return nil, errors.New("err adding w to the hash function")
	}

	if err := addStringToHash(hash, l); err != nil {
		return nil, errors.New("err adding l to the hash function")
	}

	if err := addPointToHash(hash, r1); err != nil {
		return nil, errors.New("err adding r1 to the hash function")
	}

	if err := addPointToHash(hash, w1); err != nil {
		return nil, errors.New("err adding w1 to the hash function")
	}

	if err := addPointToHash(hash, r2); err != nil {
		return nil, errors.New("err adding r2 to the hash function")
	}

	if err := addPointToHash(hash, w2); err != nil {
		return nil, errors.New("err adding w2 to the hash function")
	}

	// setByte applies mod q automatically
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

// h4Tag is the domain separation tag for the hash4 function
func h4Tag() []byte {
	return []byte("TDH2-H4")
}

// hash4 as described in the paper computes hash(xi, yi, zi) -> scalar
func hash4(
	suite Suite,
	xi, yi, zi kyber.Point,
) (kyber.Scalar, error) {

	hash := suite.Hash()
	if _, err := hash.Write(h4Tag()); err != nil {
		return nil, errors.New("err writing tag to hash")
	}

	if err := addGroupToHash(hash, suite); err != nil {
		return nil, errors.New("err adding group to the hash function")
	}

	if err := addPointToHash(hash, xi); err != nil {
		return nil, errors.New("err adding xi to the hash function")
	}

	if err := addPointToHash(hash, yi); err != nil {
		return nil, errors.New("err adding yi to the hash function")
	}

	if err := addPointToHash(hash, zi); err != nil {
		return nil, errors.New("err adding zi to the hash function")
	}

	// the hash is reduced mod q automatically
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

func addGroupToHash(h hash.Hash, group Suite) error {
	// add group name to hash
	if _, err := h.Write([]byte(group.String())); err != nil {
		return errors.New("err writing group to hash")
	}
	return nil
}

func addStringToHash(h hash.Hash, str []byte) error {
	marshalSize := make([]byte, 8)
	binary.BigEndian.PutUint64(marshalSize, uint64(len(str)))
	if _, err := h.Write(marshalSize); err != nil {
		return errors.New("err writing length of r1 to hash")
	}
	if _, err := h.Write(str); err != nil {
		return errors.New("err writing string to hash")
	}
	return nil
}

func addPointToHash(h hash.Hash, point kyber.Point) error {
	marshalSize := make([]byte, 2)
	binary.BigEndian.PutUint16(marshalSize, uint16(point.MarshalSize()))
	if _, err := h.Write(marshalSize); err != nil {
		return errors.New("err writing length of r1 to hash")
	}
	if _, err := point.MarshalTo(h); err != nil {
		return errors.New("err marshalling w1 to the hash function")
	}
	return nil
}

// xor computes and returns xor between two byte slices of equal length
func xorByteSlices(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("xor length mismatch: %d != %d", len(a), len(b))
	}
	buf := make([]byte, len(a))
	for i := range a {
		buf[i] = a[i] ^ b[i]
	}
	return buf, nil
}

// validatePoint checks if a point is valid and in the proper subgroup
// TODO: we might have more efficent ways to do this
func validatePoint(suite Suite, p kyber.Point) error {
	// first do the marshalling check
	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	// Try to interpret it back using this suite
	q := suite.Point()
	err = q.UnmarshalBinary(data)
	if err != nil {
		return err
	}

	// then also do the base check
	if !suite.Point().Base().Equal(p.Clone().Base()) {
		return errors.New("mismatch")
	}
	return nil

}
