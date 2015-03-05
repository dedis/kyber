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
// TODO Combine the valid* and Verify*
// TODO Decouple keysuite from sharesuite
// TODO It should be i >= p.n

/* The PromiseSignature object is used for insurers to express their approval
 * of a given promise. After receiving a promise and verifying that their share
 * is good, insurers can then produce a signature to send back to the promiser.
 *
 * Upon receiving this, the promiser can then add the signature to its lists of
 * signatures to server as proof that the promiser has gained a sufficient
 * number of insurers.
 */
type PromiseSignature struct {

	// The index of the insurer producing the signature
	pi int
	
	// The suite used to sign the signature
	suite abstract.Suite
	
	// The signature denoting that the insurer approves of guardining the
	// promise.
	signature []byte
}


/* Initializes a new PromiseSignature
 *
 * Arguments
 *    i   = the index of the Promise share the insurer is approving.
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

/* PromiseShare is used to represent a secret share of a Promise. When a
 * insurer wants to reveal the secret share it is guarding either to a
 * client or to other insurers to prove that the promiser is crooked, it
 * constructs this object.
 *
 * The key features of a PromiseShare are:
 *	1. The index of the share
 *      2. The share itself
 *      3. The Diffie-Hellman secret between the insurer and promiser
 *
 * #3 is used for verification purposes. Other servers can use it to prove that
 * encrypting #2 with #3 will produce the secret stored in the promise.
 *
 * As mentioned above, PromiseShare's can also be used as "BlameProof" objects.
 *
 * The BlameProof object provides an accountability measure. If a promiser
 * decides to construct a faulty share, insurers can construct a BlameProof
 * to show that the server is malicious. 
 * 
 * The insurer provides the index of the bad secret, the bad secret itself,
 * and its diffie-hellman shared key with the promiser. Other servers can then
 * verify if the promiser is malicious or the insurer is falsely accusing the
 * server.
 *
 * To quickly summarize the blame procedure, two things must hold for the blame
 * to succeed:
 *
 *   1. The provided share when encrypted with the diffie key must equal the
 *   point provided at index bi of the promise. This verifies that the share
 *   was actually intended for the insurer.
 *
 *   2. The provided share must fail to pass pubPoly.Check. This ensures that
 *   the share is actually corrupted and the insurer is not just lying.
 */

type PromiseShare struct {

	// The index of the share
	i int
	
	// The actual share from the insurer
	share abstract.Secret
	
	// The Diffie-Hellman key between insurer i and the promiser.
	diffieKey abstract.Point
}


/* Initializes a new PromiseShare
 *
 * Arguments
 *    i   = the index of the Promise share the insurer is revealing
 *    s   = the share being revealed
 *    d   = the Diffie-Hellman key between the insurer and promiser
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

/* Promise objects are mechanism by which servers can promise that a certain
 * private key or abstract.Secret can be recomputed by other servers in case
 * the original server goes offline.
 *
 * The Promise struct handles the logic of creating private shares, splitting
 * these shares up for a given number of servers to act as insurers, verifying
 * promises, and providing proof that insurers have indeed taken out approved
 * of backing up the promse.
 *
 * Terms:
 *   promiser = the server making the promise. The own who owns this object.
 *   client = recipients of the promise (aka the clients of the promiser)
 *   insurer = another server who receives a share of the promise and can help
 *              reconstruct it.
 *
 * Development note: The insurers, secrets, and signatures arrays should
 *                   remain synchronized. In other words, the insurers[i],
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
	// active. t <= r <= n
	r int
	
	// The total number of shares to send.
	n int
	
	// The public key of the promiser.
	pubKey abstract.Point
	
	// The public polynomial that is used to verify that a secret share
	// given did indeed come from the appropriate private key.
	pubPoly *poly.PubPoly
	
	// The list of servers who act as insurers of the secret. They will
	// each hold a secret that can be used to decode the promise. The list
	// is identified by the public key of the serers.
	insurers   []abstract.Point
	
	// The list of secret shares to be sent to the insurers. They are
	// encrypted with diffie-hellmen shared secrets between the insurer
	// and the original server.
	secrets    []abstract.Secret
}

/* Initializes a new promise to guard a secret.
 *
 * Arguments
 *    priKey   = the secret to be promised.
 *    t        = the minimum number of shares needed to reconstruct the secret.
 *    r        = the minimum signatures from insurers needed for the promise to
 *               be valid.
 *    insurers = a list of the public keys of servers to act as insurers.
 *
 * Returns
 *   The initialized promise
 *
 * Note
 *   Since shares will be multiplied by Diffie-Hellman keys, they need to be the
 *   same group as the keys.
 */
func (p *Promise) Init(keyPair *config.KeyPair, t, r int,
	insurers []abstract.Point) *Promise {

	// Basic initialization
	p.id = keyPair.Public.String() +
	       time.Now().Format("2006-01-02T15:04:05.999999-07:00") + 
	       strconv.FormatUint(random.Uint64(random.Stream), 10)

	p.t          = t
	p.r          = r
	p.n          = len(insurers)
	p.shareSuite = keyPair.Suite
	p.pubKey     = keyPair.Public
	p.insurers  = insurers
	p.secrets    = make([]abstract.Secret, p.n , p.n )

	// Verify that t <= r <= n
	if p.n  < p.t {
		panic("Not enough insurers for the secret")
	} 
	if p.r < p.t {
		p.r = p.t
	}
	if p.r > p.n {
		p.r = p.n
	}

	// Create the public polynomial and private shares. The total shares made
	// should be equal to teh number of insurers while the minimum shares
	// needed to reconstruct should be t.
	pripoly   := new(poly.PriPoly).Pick(p.shareSuite, p.t, keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, p.n)
	p.pubPoly = new(poly.PubPoly).Commit(pripoly, nil)
	
	// Populate the secrets array. It encrypts each share with a diffie
	// hellman exchange between the originator of the promist and the
	// specific insurer.
	for i := 0 ; i < p.n; i++ {
		diffieBase := p.shareSuite.Point().Mul(insurers[i], keyPair.Secret)
		p.secrets[i] = p.diffieHellmanEncrypt(prishares.Share(i), diffieBase)
	}
	
	return p
}

// Returns the id of the policy
func (p *Promise) GetId() string {
	return p.id
}

/* Verifies at a basic level that the Promise was constructed correctly.
 *
 * Arguments
 *    promiserKey = the key the caller believes the Promise to be from
 *
 * Return
 *   whether the promise is valid or not
 */
func (p *Promise) VerifyPromise(promiserKey abstract.Point) bool {
	// Verify t <= r <= n
	if p.t > p.n || p.t > p.r || p.r > p.n {
		return false
	}
	if !promiserKey.Equal(p.pubKey) {
		return false
	}
	// There should be a secret and public key for each of the n insurers. 
	if len(p.insurers) != p.n || len(p.secrets) != p.n {
		return false
	}
	return true
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


/* Verify that a share has been properly constructed.
 *
 * Arguments
 *    i         = the index of the share to verify
 *    gKeyPair  = the key pair of the insurer of share i
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
	if i < 0 || i >= p.n {
		return false
	}
	if !p.insurers[i].Equal(gKeyPair.Public) {
		return false
	}
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return p.pubPoly.Check(i, share)
}


/* Produce a signature for a given insurer
 *
 * Arguments
 *    i         = the index of the insurer's share
 *    gKeyPair  = the public/private keypair of the insurer.
 *
 * Return
 *   A PromiseSignature object with the signature.
 *
 * Note:
 *   The signature message will always be of the form:
 *      insurer approves PromiseId
 *
 *   It is assumed that the insurer has called VerifyShare first and hence
 *   it is assumed that the input to the function is trusted.
 */
func (p *Promise) Sign(i int, gKeyPair *config.KeyPair) *PromiseSignature {
	set        := anon.Set{gKeyPair.Public}
	approveMsg := gKeyPair.Public.String() + " approves " + p.id
	sig        := anon.Sign(gKeyPair.Suite, random.Stream, []byte(approveMsg),
		set, nil, 0, gKeyPair.Secret)
		
	return new(PromiseSignature).Init(i, gKeyPair.Suite, sig)
}

/* Verifies a signature from a given insurer
 *
 * Arguments
 *    sig = the PromiseSignature object containing the signature
 *
 * Return
 *   whether or not the signature is valid
 */
func (p *Promise) VerifySignature(sig *PromiseSignature) bool {
	if sig.signature == nil {
		return false
	}
	if sig.pi < 0 || sig.pi >= p.n {
		return false
	}
	set := anon.Set{p.insurers[sig.pi]}
	approveMsg := p.insurers[sig.pi].String() + " approves " + p.id
	_, err := anon.Verify(sig.suite, []byte(approveMsg), set, nil, sig.signature)
	return err == nil
}

/* Reveals the secret share that the insurer has been protecting. The insurer
 * decodes the secret and provides the Diffie-Hellman secret between it and
 * the promiser so that anyone receiving the secret share can confirm that it
 * is valid.
 *
 * Arguments
 *    i        = the index of the insurer
 *    gkeyPair = the keypair of the insurer
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

/* Create a proof that the promiser maliciously constructed a given secret.
 *
 * Arguments
 *    i         = the index of the malicious secret
 *    gKeyPair  = the key pair of the insurer of share i
 *
 * Return
 *   A proof object that the promiser is malicious
 */
func (p *Promise) Blame(i int, gKeyPair *config.KeyPair) *PromiseShare {
	return p.RevealShare(i, gKeyPair)
}


/* Verify that a blame proof is jusfitied.
 *
 * Arguments
 *    proof = proof that alleges that a promiser constructed a bad share.
 *
 * Return
 *   Whether the alleged share is actually corrupted or not.
 */
func (p *Promise) BlameVerify(proof *PromiseShare) bool {

	// If the index is invalid, the sender produced a malform blame proof.
	if proof.i > p.n || proof.i < 0 {
		return false
	}

	// Verify that the share given is actually the share the promiser
	// provided in the promise.
	badSecret    := p.diffieHellmanEncrypt(proof.share, proof.diffieKey)
	if !badSecret.Equal(p.secrets[proof.i]) {
		return false
	}
	
	// The diffie key should have been properly made. If not, the blamer is
	// crooked.
//	correctDiffie := p.shareSuite.Point().Add(p.insurers[proof.i], p.pubKey)
//	if !correctDiffie.Equal(proof.diffieKey) {
//		return false
//	}

	// If so, see whether the bad share fails to pass pubPoly.Check. If it
	// fails, the blame is valid. If the check succeeds, the blame was
	// unjustified.
	return !p.pubPoly.Check(proof.i, proof.share)
}


/* The PromiseState object is responsible for maintaining state for a given
 * Promise object. It will contain three main pieces:
 *
 *    1. The promise itself, which will be an immutable object 
 *    2. Shares of the private secret the server has received so far
 *    3. A list of signatures from insurers cerifying the promise
 *
 * Each server will contain a PromiseState for each promise to be tracked.
 */
type PromiseState struct {

	// The actual promise
	Promise *Promise
	
	// Primarily for use by clients, this contains shares the client
	// has currently obtained from insurers. This is what will be used to
	// reconstruct the secret.
	PriShares * poly.PriShares
	
	// A list of signatures validating that an insurer has cerified the
	// secret share it is guarding.
	signatures []*PromiseSignature
}



func (ps *PromiseState) Init(promise *Promise) *PromiseState {

	ps.Promise = promise
	
	// Initialize a new PriShares based on information from the promise
	// object.
	ps.PriShares = new(poly.PriShares)
	ps.PriShares.Empty(promise.shareSuite, promise.t, promise.n)

	// There will be at most n signatures, one per insurer
	ps.signatures = make([]*PromiseSignature, promise.n , promise.n )
	return ps
}


/* To add a share to PriShares, do:
 *
 *     p.PriShares.SetShare(index, share)
 *
 * To reconstruct the secred, do:
 *
 *     p.PriShares.Secret()
 *
 * Be warned that Secret will panic unless there are enough
 * shares to reconstruct the secret.
 */


/* Adds a signature from an insurer to the PromiseState
 *
 * Arguments
 *    sig = the PromiseSignature to add
 *
 * Postcondition
 *   The signature has been added
 *
 * Note
 *   Be sure to call ps.Promise.VerifySignature before calling this function
 */
func (ps *PromiseState) AddSignature(sig *PromiseSignature) {
	ps.signatures[sig.pi] = sig
}

/* Checks whether the Promise object has received enough signatures to be
 * considered certified.
 *
 * Arguments
 *   promiserKey = the public key the server believes the promise to have come
 *                 from
 *
 * Return
 *   whether the Promise is now cerified and considered trustworthy.
 *
 * Technical Notes: The function goes through the list of signatures and checks
 *                  whether the signature is properly signed. If at least r of
 *                  these are signed and r is greater than t (the minimum number
 *                  of shares needed to reconstruct the secret), the promise is
 *                  considered valid.
 */
func (ps *PromiseState) PromiseCertified(promiserKey abstract.Point) bool {
	if !ps.Promise.VerifyPromise(promiserKey) {
		return false
	}

	validSigs := 0
	for i := 0; i < ps.Promise.n; i++ {
		// Check whether the signature is initialized. Otherwise, bad
		// things will happen.
		if ps.signatures[i] != nil && ps.Promise.VerifySignature(ps.signatures[i]) {
			validSigs += 1
		}
	}
	return validSigs >= ps.Promise.r
}
