package promise

import (
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strconv"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
)

// TODO Pass BlameProof as pointer. Consider generalizing it.
// TODO Add Equal, Marshal, and UnMarshal methods for all
// TODO Add tests for things I haven't yet.
// TODO In tests, only use basicPromise if you ain't going to change it.
// TODO Check the valdidity of PromiseSignature and BlameProof more extensively.
//      make sure same suite, index proper, etc.
// TODO Create valid promise to do basic sanity checking.

/* The PromiseSignature object is used for guardians to express their approval
 * of a given promise. After receiving a promise and verifying that their share
 * is good, guardians can then produce a signature to send back to the promiser.
 *
 * Upon receiving this, the promiser can then add the signature to its lists of
 * signatures to server as proof that the promiser has gained a sufficient
 * number of guardians.
 */
type PromiseSignature struct {

	// The index of the guardian producing the signature
	pi int
	
	// The suite used to sign the signature
	suite abstract.Suite
	
	// The signature denoting that the guardian approves of guardining the
	// promise.
	signature []byte
}


/* Initializes a new PromiseSignature
 *
 * Arguments
 *    i   = the index of the Promise share the guardian is approving.
 *    s   = the signing suite
 *    sig = the signature of approval
 *
 * Returns
 *   An initialized PromiseSignature
 */
func (p *PromiseSignature) Init(i int, suite abstract.Suite, sig []byte) *PromiseSignature {
	p.pi        = i
	p.suite     = suite
	p.signature = sig
	return p
}


/* An initialization function for preparing a PromiseSignature for unmarshalling
 *
 * Arguments
 *    s   = the signing suite
 *
 * Returns
 *   An initialized PromiseSignature ready to be unmarshalled
 */
func (p *PromiseSignature) UnMarshalInit(suite abstract.Suite) *PromiseSignature {
	p.suite     = suite
	return p
}

// Tests whether two promise signatures are equal.
func (p *PromiseSignature) Equal(p2 *PromiseSignature) bool {
	return p.pi == p2.pi && p.suite == p2.suite &&
	       reflect.DeepEqual(p, p2)
}

// Return the encoded length of this polynomial commitment.
func (p *PromiseSignature) MarshalSize() int {
	// PutVarint will put a different amount of bytes depending upon
	// the size of the integer. Hence, the integer needs to be put into
	// a buffer and the number of bytes returned to calculate marshal size
	// Furthermore, the length of the signature is included so that
	// unmarshal can determine how great a buffer it needs.
	intSize := binary.Size(int64(p.pi))
	buf := make([]byte, intSize)
	piLen  := binary.PutVarint(buf, int64(p.pi))
	sigLen := binary.PutVarint(buf, int64(len(p.signature)))
	return piLen + sigLen + len(p.signature)
}

// Encode this polynomial into a byte slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.MarshalSize())

	// Commit the index to the buffer.
	piLen := binary.PutVarint(buf, int64(p.pi))

	// Commit the length of the signature to the buffer.
	sigLen := binary.PutVarint(buf[piLen:], int64(len(p.signature)))

	// Commit the signature to the buffer
	copy(buf[piLen+sigLen:], p.signature)
	return buf, nil
}

// Decode this polynomial from a slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) UnmarshalBinary(buf []byte) error {

	// The buffer should be at least bytes long. At minimum, a byte is
	// needed to encode the signature index, one is needed for the signature
	// length, and the final for the actual signature (though more should
	// ideally be given)
	if len(buf) < 3 {
		return errors.New("Buffer size too small")
	}

	result, bytesRead := binary.Varint(buf)
	if bytesRead <= 0 {
		return errors.New("Error decoding index")
	}
	p.pi = int(result)
	
	// The length of the signature is not needed for simple unmarshalling
	// since the buf given above should only contain data about this object.
	// Hence, anything left is a part of the signature.
	_, bytesRead2 := binary.Varint(buf[bytesRead:])
	
	p.signature = buf[bytesRead+bytesRead2:]
	return nil
}

func (p *PromiseSignature) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *PromiseSignature) UnmarshalFrom(r io.Reader) (int, error) {
	// Because signatures can be of variable length, MarshalSize will not
	// work until the object has been unmarshalled. However, the size can
	// still be reconstructed.
	// The marshalled array consists of three parts:
	//   1. The index of the signature
	//   2. The length of the signature
	//   3. The signature itself
	// 1 and 2 are variable length but no more than an int64. Hence, enough
	// can be read to unmarshal 1 and 2. After that is done, the length of
	// the entire object can be recomputed. Hence, the proper buffer can
	// be made and the rest of the unmarshalling can be handled by
	// BinaryUnmarshal.
	
	// Retrieve the signature index as stated above.
	intSize    :=  binary.Size(int64(p.pi))
	buf := make([]byte, intSize*2)
	n, err := io.ReadFull(r, buf)

	if err != nil {
		return n, err
	}
	
	// Find the length of the signature index as stated above.
	_, piLen := binary.Varint(buf)
	if piLen <= 0 {
		return 0, errors.New("Binary number not provided for index")
	}
	
	// Retrieve the signature length
	sigLen, sigLenBytesRead := binary.Varint(buf[piLen:])
	if sigLenBytesRead <= 0 {
		return 0, errors.New("Signature length not provided")
	}

	// The entire length of the buffer can now be calculated and the
	// object = unmarshalled.
	finalBuf := make([]byte, int(sigLen) + piLen + sigLenBytesRead)
	
	// Copy what has already been read into the buffer.
	copy(finalBuf, buf)
	
	// Read the rest.
	m, err2 := io.ReadFull(r, finalBuf[n:])
	if err2 != nil {
		return m, err2
	}
	return n+m, p.UnmarshalBinary(finalBuf)
}


type PromiseShare struct {

	// The index of the share
	i int
	
	// The actual share from the guardian
	share abstract.Secret
	
	// The Diffie-Hellman key between guardian i and the promiser.
	diffieKey abstract.Point
}


/* Initializes a new PromiseShare
 *
 * Arguments
 *    i   = the index of the Promise share the guardian is revealing
 *    s   = the share being revealed
 *    d   = the Diffie-Hellman key between the guardian and promiser
 *
 * Returns
 *   An initialized PromiseShare
 */
func (p *PromiseShare) Init(i int, s abstract.Secret, d abstract.Point) *PromiseShare {
	p.i         = i
	p.share     = s
	p.diffieKey = d
	return p
}

// Tests whether two promise secrets are equal.
func (p *PromiseShare) Equal(p2 *PromiseShare) bool {
	return p.i == p2.i && p.share.Equal(p2.share) &&
	       p.diffieKey.Equal(p2.diffieKey)
}

/* The BlameProof object provides an accountability measure. If a promiser
 * decides to construct a faulty share, guardians can construct a BlameProof
 * to show that the server is malicious. 
 * 
 * The guardian provides the index of the bad secret, the bad secret itself,
 * and its diffie-hellman shared key with the promiser. Other servers can then
 * verify if the promiser is malicious or the guardian is falsely accusing the
 * server.
 *
 * To quickly summarize the blame procedure, two things must hold for the blame
 * to succeed:
 *
 *   1. The provided share when encrypted with the diffie key must equal the
 *   point provided at index bi of the promise. This verifies that the share
 *   was actually intended for the guardian.
 *
 *   2. The provided share must fail to pass pubPoly.Check. This ensures that
 *   the share is actually corrupted and the guardian is not just lying.
 */
type BlameProof struct {

	// The index of the share that is thought to be a bad secret
	bi int
	
	// The actual share that is thought to be bad.
	bshare abstract.Secret
	
	// The Diffie-Hellman key between guardian i and the promiser.
	diffieKey abstract.Point
}

/* Promise objects are mechanism by which servers can promise that a certain
 * private key or abstract.Secret can be recomputed by other servers in case
 * the original server goes offline.
 *
 * The Promise struct handles the logic of creating private shares, splitting
 * these shares up for a given number of servers to act as guardians, verifying
 * promises, and providing proof that guardians have indeed taken out approved
 * of backing up the promse.
 *
 * Terms:
 *   promiser = the server making the promise. The own who owns this object.
 *   promised = recipients of the promise (aka the clients of the promiser)
 *   guardian = another server who receives a share of the promise and can help
 *              reconstruct it.
 *
 * Development note: The guardians, secrets, and signatures arrays should
 *                   remain synchronized. In other words, the guardians[i],
 *                   secrets[i], and signatures[i] should all refer to the same
 *                   server.
 */
type Promise struct {

	// The id of the promise. In the format:
	//   PromiserPublicKey.String() + TimeOfCreation + RandomNumber
	id string

	// The cryptographic group to use for the private shares.
	shareSuite abstract.Suite
	
	// The minimum number of shares needed to reconstruct the secret.
	t int
	
	// The minimum number of shares needed before the policy can become
	// active. t <= r
	r int
	
	// The total number of shares to send.
	n int
	
	// The public key of the promiser.
	pubKey abstract.Point
	
	// The public polynomial that is used to verify that a secret share
	// given did indeed come from the appropriate private key.
	pubPoly *poly.PubPoly
	
	// Primarily for the promised, the number of shares that have been 
	// revealed so far.
	numShares int
	
	// Primarily for the promised, this contains the shares the promised
	// have currently obtained from guardians. This is what will be used to
	// reconstruct the secret.
	priShares * poly.PriShares
	
	// The list of servers who act as guardians of the secret. They will
	// each hold a secret that can be used to decode the promise. The list
	// is identified by the public key of the serers.
	guardians   []abstract.Point
	
	// The list of secret shares to be sent to the guardians. They are
	// encrypted with diffie-hellmen shared secrets between the guardian
	// and the original server.
	secrets    []abstract.Secret
	
	// A list of signatures validating that a guardian has approved of the
	// secret share it is guarding.
	signatures []*PromiseSignature
}

/* Initializes a new promise to guard a secret.
 *
 * Arguments
 *    priKey   = the secret to be promised.
 *    t        = the minimum number of shares needed to reconstruct the secret.
 *    r        = the minimum signatures from guardians needed for the promise to
 *               be valid.
 *    guardians = a list of the public keys of servers to act as guardians.
 *
 * Returns
 *   The initialized promise
 *
 * Note
 *   Since shares will be multiplied by Diffie-Hellman keys, they need to be the
 *   same group as the keys.
 */
func (p *Promise) Init(keyPair *config.KeyPair, t, r int,
	guardians []abstract.Point) *Promise {

	// Basic initialization
	p.id = keyPair.Public.String() +
	       time.Now().Format("2006-01-02T15:04:05.999999-07:00") + 
	       strconv.FormatUint(random.Uint64(random.Stream), 10)

	p.t          = t
	p.r          = r
	p.n          = len(guardians)
	p.shareSuite = keyPair.Suite
	p.pubKey     = keyPair.Public
	p.guardians  = guardians
	p.secrets    = make([]abstract.Secret, p.n , p.n )
	p.signatures = make([]*PromiseSignature, p.n , p.n )

	// Verify that t <= r <= n
	if p.n  < p.t {
		panic("Not enough guardians for the secret")
	} 
	if p.r < p.t {
		p.r = p.t
	}
	if p.r > p.n {
		p.r = p.n
	}

	// Create the public polynomial and private shares. The total shares made
	// should be equal to teh number of guardians while the minimum shares
	// needed to reconstruct should be t.
	pripoly   := new(poly.PriPoly).Pick(p.shareSuite, p.t, keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, p.n)
	p.pubPoly = new(poly.PubPoly).Commit(pripoly, nil)
	
	// Create an empty PriShares for the promised.
	p.numShares = 0
	p.priShares = new(poly.PriShares)
	p.priShares.Empty(p.shareSuite, p.t, p.n)
	
	// Populate the secrets array. It encrypts each share with a diffie
	// hellman exchange between the originator of the promist and the
	// specific guardian.
	for i := 0 ; i < p.n; i++ {
		diffieBase := p.shareSuite.Point().Mul(guardians[i], keyPair.Secret)
		p.secrets[i] = p.diffieHellmanEncrypt(prishares.Share(i), diffieBase)
	}
	
	return p
}

// Returns the id of the policy
func (p *Promise) GetId() string {
	return p.id
}

/* Given a Diffie-Hellman shared key, encrypts a secret.
 *
 * Arguments
 *    secret      = the secret to encrypt
 *    diffieBase  = the DH shared key
 *
 * Return
 *   the encrypted secret
 */
func (p *Promise) diffieHellmanEncrypt(secret abstract.Secret, diffieBase abstract.Point) abstract.Secret {	
	buff, err := diffieBase.MarshalBinary()
	if err != nil {
		panic("Bad shared secret for Diffie-Hellman give.")
	}
	cipher := p.shareSuite.Cipher(buff)
	diffieSecret := p.shareSuite.Secret().Pick(cipher)
	return p.shareSuite.Secret().Add(secret, diffieSecret)
}

/* Given a Diffie-Hellman shared key, decrypts a secret.
 *
 * Arguments
 *    secret      = the secret to decrypt
 *    diffieBase  = the DH shared key
 *
 * Return
 *   the decrypted secret
 */
func (p *Promise) diffieHellmanDecrypt(secret abstract.Secret, diffieBase abstract.Point) abstract.Secret {	
	buff, err := diffieBase.MarshalBinary()
	if err != nil {
		panic("Bad shared secret for Diffie-Hellman give.")
	}
	cipher := p.shareSuite.Cipher(buff)
	diffieSecret := p.shareSuite.Secret().Pick(cipher)
	return p.shareSuite.Secret().Sub(secret, diffieSecret)
}

/* This helper function makes sure that a share is "syntactically" valid. In
 * other words, the index is properly in range and the guardian it was sent to
 * the correct guardian. VerifyShare handles "semantic" verification.
 *
 * Arguments
 *   i        = the index of the share
 *   gKeyPair = the key pair of the guardian of the share
 *
 * Returns
 *    Whether the share is valid or invalid.
 */
func (p *Promise) validShare(i int, gKeyPair *config.KeyPair) bool {
	if i < 0 || i > p.n {
		return false
	}
	if !p.guardians[i].Equal(gKeyPair.Public) {
		return false
	}
	return true
}


/* Verify that a share has been properly constructed.
 *
 * Arguments
 *    i        = the index of the share to verify
 *    gPrikey  = the private key of the guardian of share i
 *
 * Return
 *   whether the decrypted secret properly passes the public polynomial.
 *
 * Note
 *   Make sure that the proper index and key is specified. Otherwise, the
 *   function will return false because diffieHellmanDecrypt gave the wrong
 *   result. In short, make sure to verify only shares that are allotted to you.
 */
func (p *Promise) VerifyShare(i int, gKeyPair *config.KeyPair) bool {
	if !p.validShare(i, gKeyPair) {
		return false
	}
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return p.pubPoly.Check(i, share)
}

/* Verifies whether a Promise objects has enough signatures to be valid.
 *
 * Return
 *   whether the Promise is now valid and considered trustworthy.
 *
 * Technical Notes: The function goes through the list of signatures and checks
 *                  whether the signature is properly signed. If at least r of
 *                  these are signed and r is greater than t (the minimum number
 *                  of shares needed to reconstruct the secret), the promise is
 *                  considered valid.
 */
func (p *Promise) VerifyPromise() bool {
	validSigs := 0
	for i := 0; i < p.n; i++ {
		// Check whether the signature is initialized. Otherwise, bad
		// things will happen.
		if p.signatures[i] != nil && p.VerifySignature(p.signatures[i]) {
			validSigs += 1
		}
	}
	return p.r > p.t && validSigs >= p.r
}

/* Produce a signature for a given guardian
 *
 * Arguments
 *    i         = the index of the guardian's share
 *    gKeyPair  = the public/private keypair of the guardian.
 *
 * Return
 *   A PromiseSignature object with the signature.
 *
 * Note:
 *   The signature message will always be of the form:
 *      Guardian approves PromiseId
 *
 *   It is assumed that the guardian has called VerifyShare first and hence
 *   it is assumed that the input to the function is trusted.
 */
func (p *Promise) Sign(i int, gKeyPair *config.KeyPair) *PromiseSignature {
	set        := anon.Set{gKeyPair.Public}
	approveMsg := gKeyPair.Public.String() + " approves " + p.id
	sig        := anon.Sign(gKeyPair.Suite, random.Stream, []byte(approveMsg),
		set, nil, 0, gKeyPair.Secret)
		
	return new(PromiseSignature).Init(i, gKeyPair.Suite, sig)
}

/* An internal helper function, makes sure that a promise signature is formatted
 * properly and that no data was sent maliciously (index out of bounds, etc.)
 *
 * Arguments
 *    sig = the PromiseSignature to check
 *
 * Return
 *   whether the PromiseSignature was formatted properly
 *
 * Note:
 *   Please see VerifySignature for more on validating signatures.
 */
func (p *Promise) validSignature(sig *PromiseSignature) bool {
	if sig.pi < 0 || sig.pi > p.n {
		return false
	}
	
	if sig.signature == nil {
		return false
	}
	
	return true
}

/* Verifies a signature from a given guardian
 *
 * Arguments
 *    sig = the PromiseSignature object containing the signature
 *
 * Return
 *   whether or not the signature is valid
 */
func (p *Promise) VerifySignature(sig *PromiseSignature) bool {
	if !p.validSignature(sig) {
		return false
	}
	set := anon.Set{p.guardians[sig.pi]}
	approveMsg := p.guardians[sig.pi].String() + " approves " + p.id
	_, err := anon.Verify(sig.suite, []byte(approveMsg), set, nil, sig.signature)
	return err == nil
}

/* Adds a signature from a guardian to the promise
 *
 * Arguments
 *    sig = the PromiseSignature to add
 *
 * Return
 *   true if inserted properly (aka the signature is valid), false otherwise.
 */
func (p *Promise) AddSignature(sig *PromiseSignature) bool {
	if !p.VerifySignature(sig) {
		return false
	}

	p.signatures[sig.pi] = sig
	return true
}

/* Reveals the secret share that the guardian has been protecting. The guardian
 * decodes the secret and provides the Diffie-Hellman secret between it and
 * the promiser so that anyone receiving the secret share can confirm that it
 * is valid.
 *
 * Arguments
 *    i        = the index of the guardian
 *    gkeyPair = the keypair of the guardian
 *
 * Return
 *   a PromiseShare object representing the share.
 */
func (p *Promise) RevealShare(i int, gKeyPair *config.KeyPair) *PromiseShare {
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share      := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return new(PromiseShare).Init(i, share, diffieBase)
}

/* Verify that PromiseShare is both syntactically and semantically wellformed.
 *
 * In particular:
 *    1. The index should be within range
 *    2. The secret provided and the Diffie-Hellman key should match the share
 *       found at the corresponding index in the Promise.
 *    3. The secret provided passes the public polynomial
 *
 * Arguments
 *    psecret = the PromiseShare to verify
 *
 * Return
 *   Whether the secret is valid
 */
func (p *Promise) PromiseShareVerify(psecret *PromiseShare) bool {

	// If the index is invalid, the sender produced a malform blame proof.
	if psecret.i > p.n || psecret.i < 0 {
		return false
	}

	// Verify that the share given is actually the share the promiser
	// provided in the promise.
	share  := p.diffieHellmanEncrypt(psecret.share, psecret.diffieKey)
	if !share.Equal(p.secrets[psecret.i]) {
		return false
	}

	// Check that the share provided passes the public polynomial
	return p.pubPoly.Check(psecret.i, psecret.share)
}

/* Adds a revealed share to the Promise's PriShare object
 *
 * This should be used primarily by the promised who are wishing to reconstruct
 * the promised secret.
 *
 * Call PromiseShareVerify before calling this function.
 *
 * Arguments
 *    psecret = the PromiseShare to add
 *
 * Postcondition
 *   The share has been added.
 */
func (p *Promise) AddRevealedSecret(psecret *PromiseShare) {
	p.priShares.SetShare(psecret.i, psecret.share)
	p.numShares += 1
}

/* Checks whether enough shares have been revealed to reconstruct the secret.
 *
 * Returns
 *   whehter the secret can be reconstructed
 */
func (p *Promise) CanReconstructSecret() bool {
	return p.numShares >= p.t
}

/* Reconstructs the promised secret (primarily for the promised)
 * 
 * Returns
 *   the actual secret that was promised
 *
 * Note:
 *   Do not call this unless CanReconstructSecret returns true. The Secret
 *   function of PriShares will panic if there are not enough shares to
 *   reconstruct the secret.
 */
func (p *Promise) ReconstructSecret() abstract.Secret {
	return p.priShares.Secret()
}


/* Create a proof that the promiser maliciously constructed a given secret.
 *
 * Arguments
 *    i        = the index of the malicious secret
 *    gPrikey  = the private key of the guardian of share i
 *
 * Return
 *   A proof object that has the index and the decoded share.
 */
func (p *Promise) Blame(i int, gPrikey abstract.Secret) BlameProof {
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gPrikey)
	share := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return BlameProof{bi: i, bshare: share, diffieKey: diffieBase}
}


/* Verify that a blame proof is jusfitied.
 *
 * Arguments
 *    proof = proof that alleges that a promiser constructed a bad share.
 *
 * Return
 *   Whether the alleged share is actually corrupted or not.
 */
func (p *Promise) BlameVerify(proof BlameProof) bool {

	// If the index is invalid, the sender produced a malform blame proof.
	if proof.bi > p.n || proof.bi < 0 {
		return false
	}

	// Verify that the share given is actually the share the promiser
	// provided in the promise.
	badSecret    := p.diffieHellmanEncrypt(proof.bshare, proof.diffieKey)
	if !badSecret.Equal(p.secrets[proof.bi]) {
		return false
	}

	// If so, see whether the bad share fails to pass pubPoly.Check. If it
	// fails, the blame is valid. If the check succeeds, the blame was
	// unjustified.
	return !p.pubPoly.Check(proof.bi, proof.bshare)
}

