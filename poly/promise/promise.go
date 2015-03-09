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

var sigMsg []byte = []byte("Prifi Insurance Signatures")

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


var uint32Size = binary.Size(uint32(0))

/* The PromiseSignature object is used for insurers to express their approval
 * of a given promise. After receiving a promise and verifying that their share
 * is good, insurers can then produce a signature to send back to the promiser.
 *
 * Upon receiving this, the promiser can then add the signature to its lists of
 * signatures to server as proof that the promiser has gained a sufficient
 * number of insurers.
 */
type PromiseSignature struct {
	
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
func (p *PromiseSignature) Init(suite abstract.Suite, sig []byte) *PromiseSignature {
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
func (p *PromiseSignature) UnmarshalInit(suite abstract.Suite) *PromiseSignature {
	p.suite     = suite
	return p
}

// Tests whether two promise signatures are equal.
func (p *PromiseSignature) Equal(p2 *PromiseSignature) bool {
	return p.suite == p2.suite &&
	       reflect.DeepEqual(p, p2)
}

// Return the encoded length of this polynomial commitment.
func (p *PromiseSignature) MarshalSize() int {
	return uint32Size + len(p.signature)
}

// Encode this polynomial into a byte slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.MarshalSize())
	binary.LittleEndian.PutUint32(buf, uint32(len(p.signature)))
	copy(buf[uint32Size:], p.signature)
	return buf, nil
}

// Decode this polynomial from a slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) UnmarshalBinary(buf []byte) error {

	uint32Size := binary.Size(uint32(0))

	// The buffer should be at least be able to hold a uint32 and a
	// byte message at least 1 byte long (preferably more)
	if len(buf) < uint32Size + 1 {
		return errors.New("Buffer size too small")
	}

	// Signature length is not needed for unmarshalling proper since all of
	// the remaining buffer will be used for the signature.
	p.signature = buf[uint32Size:]
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
	// work until the object has been unmarshalled. However, the size of the
	// signature is provided as a unit32 at the beginning of the message.
	
	// Retrieve the signature length
	buf := make([]byte, uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	
	sigLen := binary.LittleEndian.Uint32(buf)

	// Calculate the length of the entire message and create the new buffer.
	finalBuf := make([]byte, uint32Size + int(sigLen))
	
	// Copy what has already been read into the buffer.
	copy(finalBuf, buf)
	
	// Read the rest and unmarshal.
	m, err2 := io.ReadFull(r, finalBuf[n:])
	if err2 != nil {
		return m, err2
	}
	return n+m, p.UnmarshalBinary(finalBuf)
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

/* To be called by the promiser, initializes a new promise to guard a secret.
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
func (p *Promise) PromiserInit(keyPair *config.KeyPair, t, r int,
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
 *   an error if the promise is malformed, nil otherwise.
 */
func (p *Promise) VerifyPromise(promiserKey abstract.Point) error {
	// Verify t <= r <= n
	if p.t > p.n || p.t > p.r || p.r > p.n {
		return errors.New("Invalid t-of-n shares promise: expected t <= r <= n")
	}
	if !promiserKey.Equal(p.pubKey) {
		return errors.New("Public key of promise differs from what is expected")
	}
	// There should be a secret and public key for each of the n insurers. 
	if len(p.insurers) != p.n || len(p.secrets) != p.n {
		return errors.New("Insurers and secrets array should be of length promise.n")
	}
	return nil
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


/* Verify that a share has been properly constructed. This should be called by
 * insurers to verify that the share they insure is properly constructed.
 *
 * Arguments
 *    i         = the index of the share to verify
 *    gKeyPair  = the key pair of the insurer of share i
 *
 * Return
 *  an error if the promise is malformed, nil otherwise.
 *
 * Note
 *   Make sure that the proper index and key is specified. Otherwise, the
 *   function will return false because diffieHellmanDecrypt gave the wrong
 *   result. In short, make sure to verify only shares that are allotted to you.
 */
func (p *Promise) VerifyShare(i int, gKeyPair *config.KeyPair) error {
	if i < 0 || i >= p.n {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	msg := "The public key the promise recorded for this" +
	       "shares differs from what is expected"
	if !p.insurers[i].Equal(gKeyPair.Public) {
		return errors.New(msg)
	}
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	if !p.pubPoly.Check(i, share) {
		return errors.New("The share failed the public polynomial check.")
	}
	return nil
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
	sig        := anon.Sign(gKeyPair.Suite, random.Stream, sigMsg,
		set, nil, 0, gKeyPair.Secret)	
	return new(PromiseSignature).Init(gKeyPair.Suite, sig)
}

/* Verifies a signature from a given insurer
 *
 * Arguments
 *    i   =
 *    sig = the PromiseSignature object containing the signature
 *
 * Return
 *   an error if the promise is malformed, nil otherwise.
 */
func (p *Promise) VerifySignature(i int, sig *PromiseSignature) error {
	if sig.signature == nil {
		return errors.New("Nil signature")
	}
	if i < 0 || i >= p.n {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	set := anon.Set{p.insurers[i]}
	_, err := anon.Verify(sig.suite, sigMsg, set, nil, sig.signature)
	return err
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
 *   the revealed private share
 */
func (p *Promise) RevealShare(i int, gKeyPair *config.KeyPair) abstract.Secret {
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share      := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return share
}

/* Verify that a revealed share is properly formed. This should be calle by
 * clients or others who request an insurer to reveal its secret.
 *
 * Arguments
 *    i     = the index of the share
 *    share = the share to validate.
 *
 * Return
 *   Whether the secret is valid
 */
func (p *Promise) VerifyRevealedShare(i int, share abstract.Secret) error {
	if i > p.n || i < 0 {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	if !p.pubPoly.Check(i, share) {
		return errors.New("The share failed the public polynomial check.")
	}
	return nil
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
//func (p *Promise) Blame(i int, gKeyPair *config.KeyPair) *PromiseShare {
//	return p.RevealShare(i, gKeyPair)
//}


/* Verify that a blame proof is jusfitied.
 *
 * Arguments
 *    proof = proof that alleges that a promiser constructed a bad share.
 *
 * Return
 *   Whether the alleged share is actually corrupted or not.
 */
//func (p *Promise) BlameVerify(proof *PromiseShare) bool {

	// If the index is invalid, the sender produced a malform blame proof.
//	if proof.i > p.n || proof.i < 0 {
//		return false
//	}

	// Verify that the share given is actually the share the promiser
	// provided in the promise.
//	badSecret    := p.diffieHellmanEncrypt(proof.share, proof.diffieKey)
//	if !badSecret.Equal(p.secrets[proof.i]) {
//		return false
//	}
	
	// The diffie key should have been properly made. If not, the blamer is
	// crooked.
//	correctDiffie := p.shareSuite.Point().Add(p.insurers[proof.i], p.pubKey)
//	if !correctDiffie.Equal(proof.diffieKey) {
//		return false
//	}

	// If so, see whether the bad share fails to pass pubPoly.Check. If it
	// fails, the blame is valid. If the check succeeds, the blame was
	// unjustified.
//	return !p.pubPoly.Check(proof.i, proof.share)
//}


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
 *    i   = the index in the signature array this signature belogns
 *    sig = the PromiseSignature to add
 *
 * Postcondition
 *   The signature has been added
 *
 * Note
 *   Be sure to call ps.Promise.VerifySignature before calling this function
 */
func (ps *PromiseState) AddSignature(i int, sig *PromiseSignature) {
	ps.signatures[i] = sig
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
func (ps *PromiseState) PromiseCertified(promiserKey abstract.Point) error {
	if err := ps.Promise.VerifyPromise(promiserKey); err != nil {
		return err
	}

	validSigs := 0
	for i := 0; i < ps.Promise.n; i++ {
		// Check whether the signature is initialized. Otherwise, bad
		// things will happen.
		if ps.signatures[i] != nil &&
		   ps.Promise.VerifySignature(i, ps.signatures[i]) == nil {
			validSigs += 1
		}
	}
	if validSigs < ps.Promise.r {
		return errors.New("Not enough signatures yet to be certified")
	}
	return nil
}

