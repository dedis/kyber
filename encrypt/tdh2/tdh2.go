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
// In the future this implementation can be updated to benefit from
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

	hashFunctionFailureErrorMessageWrapper = "hash%d failed: %w"
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

// Parameters represents the public parameters of the scheme that are needed for encryption and decryption
type Parameters struct {
	Threshold    int           // threshold for decryption (for N check the len of publicKeys)
	UseAESGCM    bool          // whether to use AES-GCM for encryption/decryption instead of one-time-pad
	PublicKey    kyber.Point   // public key corresponding to the private key that encrypts the message
	PublicShares []kyber.Point // public keys corresponding to the private key shares of each participant, order matters
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
	params Parameters,
	message []byte,
	label []byte,
) (*CipherText, error) {
	randomStream := suite.RandomStream()

	// generate a random scalar for ephemeral private key
	r := suite.Scalar().Pick(randomStream)
	s := suite.Scalar().Pick(randomStream)

	// ephemeral DH shared secret (ss = g^{r . pk})
	// where pk is the public key and r is a random scalar
	ss := suite.Point().Mul(r, params.PublicKey)

	var w []byte
	var p int
	if params.UseAESGCM { // if aes gcm is requested
		// generate random nonce for AES-GCM
		nonce := make([]byte, NonceSize)
		random.Bytes(nonce, randomStream)

		// hash the ephemeral shared secret and produce aes key
		aesKey, err := hash1(suite, ss, AESBytes)
		if err != nil {
			return nil, fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 1, err)
		}

		// setup AES GCM
		aead, err := newAEAD(suite, aesKey)
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
			padded := make([]byte, len(message)+p)
			copy(padded, message)
			message = padded
		}

		// apply hash and cut to the length of message
		hashed, err := hash1(suite, ss, len(message))
		if err != nil {
			return nil, fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 1, err)
		}

		// H1(h^r) ⊕ m
		w, err = xorByteSlices(hashed, message)
		if err != nil {
			return nil, fmt.Errorf("xor failed: %w", err)
		}
	}

	r1 := suite.Point().Mul(r, nil)              // r1 = r . G
	r2 := suite.Point().Mul(r, params.PublicKey) // r2 = r . pub

	w1 := suite.Point().Mul(s, nil)              // w1 = s . G
	w2 := suite.Point().Mul(s, params.PublicKey) // w2 = s . pub

	e, err := hash2(suite, w, label, p, params.PublicKey, r1, w1, r2, w2)
	if err != nil {
		return nil, fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 2, err)
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
	params Parameters,
	ct *CipherText,
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
		suite.Point().Mul(ct.F, params.PublicKey),
		suite.Point().Mul(ct.E, ct.R2),
	)

	e, err := hash2(suite, ct.W, ct.L, ct.P, params.PublicKey, ct.R1, w1, ct.R2, w2)
	if err != nil {
		return fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 2, err)
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
	params Parameters,
	ct *CipherText,
	index uint32, // index
	ski kyber.Scalar, // private key share i
	expectedLabel []byte,
) (*PartialDecryptionShare, error) {
	if err := Verify(suite, params, ct, expectedLabel); err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// generate a random scalar for ephemeral private key
	si := suite.Scalar().Pick(suite.RandomStream())

	xi := suite.Point().Mul(ski, ct.R1) // X_i = sk_i * r1
	yi := suite.Point().Mul(si, ct.R1)  // y_i = s_i * r1
	zi := suite.Point().Mul(si, nil)    // z_i = s_i * G

	// compute hash4
	pki := suite.Point().Mul(ski, nil)
	ei, err := hash4(suite, ct.R1, pki, index, xi, yi, zi)
	if err != nil {
		return nil, fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 4, err)
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

	expectedEi, err := hash4(suite, ct.R1, pki, partial.Index, partial.Xi, yi, zi)
	if err != nil {
		return fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 4, err)
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
	params Parameters,
	ct *CipherText,
	partials []*PartialDecryptionShare,
	expectedLabel []byte,
) (msg []byte, validPartials int, err error) {
	// verify ciphertext
	if err := Verify(suite, params, ct, expectedLabel); err != nil {
		return nil, 0, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// verify partials validatity and meeting the threshold requirement
	shares, err := verifyPartials(suite, params, ct, partials)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to verify partial decryptions: %w", err)
	}

	// Recover the shared secret (Lagrange interpolation in the exponent)
	v, err := share.RecoverCommit(suite, shares, uint32(params.Threshold), uint32(len(params.PublicShares)))
	if err != nil {
		return nil, 0, err
	}

	// message recovery step
	if params.UseAESGCM {
		// decrypt the ciphertext using AES-GCM
		aesKey, err := hash1(suite, v, AESBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("h1 failed: %w", err)
		}
		aead, err := newAEAD(suite, aesKey)
		if err != nil {
			return nil, 0, err
		}
		// split w into Nonce and c
		if len(ct.W) < NonceSize+16 { // AES-GCM tag is 16 bytes
			return nil, 0, fmt.Errorf("ct.w too short")
		}
		nonce, c := ct.W[:NonceSize], ct.W[NonceSize:]

		plaintext, err := aead.Open(nil, nonce, c, expectedLabel)
		if err != nil {
			return nil, 0, err
		}
		return plaintext, len(shares), nil
	}

	// else
	hashed, err := hash1(suite, v, len(ct.W))
	if err != nil {
		return nil, 0, fmt.Errorf(hashFunctionFailureErrorMessageWrapper, 1, err)
	}

	message, err := xorByteSlices(hashed, ct.W)
	if err != nil {
		return nil, 0, fmt.Errorf("xor failed: %w", err)
	}
	// strip out the extra padding
	if ct.P < 0 || ct.P > len(message) {
		return nil, 0, fmt.Errorf("invalid padding length")
	}
	return message[:len(message)-ct.P], len(shares), nil
}

func verifyPartials(
	suite Suite,
	params Parameters,
	ct *CipherText,
	partials []*PartialDecryptionShare,
) (validPartials []*share.PubShare, err error) {
	validShares := make([]*share.PubShare, 0)
	seen := make(map[uint32]bool)
	for i := 0; i < len(partials); i++ {

		// fetch public key
		idx := partials[i].Index
		if seen[idx] {
			continue // skip duplicate shares for the same index
		}
		if int(idx) >= len(params.PublicShares) {
			return nil, fmt.Errorf("invalid index")
		}
		qi := params.PublicShares[idx]

		if err := VerifyPartialDecryptionShare(suite, ct, partials[i], qi); err != nil {
			// skip the partial share
			continue
		}
		seen[idx] = true
		validShares = append(validShares, &share.PubShare{I: idx, V: partials[i].Xi})
	}
	// quorum check
	if len(validShares) < params.Threshold {
		return nil, fmt.Errorf("not enough valid partial decryptions %d < %d", len(validShares), params.Threshold)
	}
	return validShares, nil
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
		return nil, errors.New("err writing h1 tag to hash")
	}

	// add group name to hash
	if err := addGroupToHash(hash, suite); err != nil {
		return nil, err
	}

	// add point encoding size
	if err := addPointToHash(hash, point); err != nil {
		return nil, err
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
	// In the futuer we may want to use the random package in utils
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
// modified to include padding p and public key pk
func hash2(
	suite Suite,
	w, l []byte,
	p int,
	pk, r1, w1, r2, w2 kyber.Point,
) (kyber.Scalar, error) {
	hash := suite.Hash()
	if _, err := hash.Write(h2Tag()); err != nil {
		return nil, err
	}

	if err := addGroupToHash(hash, suite); err != nil {
		return nil, err
	}

	if err := addStringToHash(hash, w); err != nil {
		return nil, err
	}

	if err := addStringToHash(hash, l); err != nil {
		return nil, err
	}

	pBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pBytes, uint32(p))
	if _, err := hash.Write(pBytes); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, pk); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, r1); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, w1); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, r2); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, w2); err != nil {
		return nil, err
	}

	// setByte applies mod q automatically
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

// h4Tag is the domain separation tag for the hash4 function
func h4Tag() []byte {
	return []byte("TDH2-H4")
}

// hash4 as described in the paper computes hash(xi, yi, zi) -> scalar
// modified to include statement bases r1, pki and index i
func hash4(
	suite Suite,
	r1, pki kyber.Point,
	index uint32,
	xi, yi, zi kyber.Point,
) (kyber.Scalar, error) {
	hash := suite.Hash()
	if _, err := hash.Write(h4Tag()); err != nil {
		return nil, err
	}

	if err := addGroupToHash(hash, suite); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, r1); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, pki); err != nil {
		return nil, err
	}

	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, index)
	if _, err := hash.Write(idxBytes); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, xi); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, yi); err != nil {
		return nil, err
	}

	if err := addPointToHash(hash, zi); err != nil {
		return nil, err
	}

	// the hash is reduced mod q automatically
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

func addGroupToHash(h hash.Hash, group Suite) error {
	// add group name to hash
	if _, err := h.Write([]byte(group.String())); err != nil {
		return fmt.Errorf("err writing group info to hash: %w", err)
	}
	return nil
}

func addStringToHash(h hash.Hash, str []byte) error {
	marshalSize := make([]byte, 8)
	binary.BigEndian.PutUint64(marshalSize, uint64(len(str)))
	if _, err := h.Write(marshalSize); err != nil {
		return fmt.Errorf("err writing length of string to hash: %w", err)
	}
	if _, err := h.Write(str); err != nil {
		return fmt.Errorf("err writing string to hash: %w", err)
	}
	return nil
}

func addPointToHash(h hash.Hash, point kyber.Point) error {
	marshalSize := make([]byte, 2)
	binary.BigEndian.PutUint16(marshalSize, uint16(point.MarshalSize()))
	if _, err := h.Write(marshalSize); err != nil {
		return fmt.Errorf("err writing length of point to hash: %w", err)
	}
	if _, err := point.MarshalTo(h); err != nil {
		return fmt.Errorf("err marshalling point to the hash function: %w", err)
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
		return errors.New("point base mismatch")
	}
	return nil

}

func newAEAD(suite Suite, aesKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
