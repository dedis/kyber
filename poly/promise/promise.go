package promise

import (
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
func (p *PromiseSignature) Init(i int, sig []byte) *PromiseSignature {
	p.pi        = i
	p.signature = sig
	return p
}

// Tests whether two promise signatures are equal.
func (p *PromiseSignature) Equal(p2 *PromiseSignature) bool {
	return p.pi == p2.pi && reflect.DeepEqual(p, p2)
}

// Return the encoded length of this polynomial commitment.
func (p *PromiseSignature) MarshalSize() int {
	return reflect.TypeOf(int).Size() + len(p.signature)
}

// Encode this polynomial into a byte slice exactly Len() bytes long.
func (p *PromiseSignature) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.MarshalSize())

	// Commit the index to the buffer.	
	copy(buf, []byte(p.pi))
	index := reflect.TypeOf(int).Size()

	// Commit the signature to the buffer
	index += p.suite.MarshalSize()
	copy(buf[index:], signature)
	return buf, nil
}

// Decode this polynomial from a slice exactly Len() bytes long.
func (p *PromiseSignature) UnmarshalBinary(buf []byte) error {
	intSize    := reflect.TypeOf(int).Size()
	suiteSize :=  p.suite.MarshalSize()
	
	// The signature should at least be the size of the suite, an integer
	// to contain the index, and at least one space for the signature
	// (though the signature should be much larger realistically)
	if len(buf) < intSize + suiteSize + 1 {
		return err("Buffer size too small")
	}
	
	p.pi = int(buf[:intSize])
	if err := p.suite.UnmarshalBinary(buf[intSize : suiteSize); err != nil {
		return err
	}
	p.signature = buf[intSize + suiteSize:]
	return nil
}

func (p *PromiseSignature) MarshalTo(w io.Writer) (int, error) {
	buf, err := pub.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(pubb)
}

func (p *PromiseSignature) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
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
func (p *Promise) VerifyShare(i int, gPrikey abstract.Secret) bool {
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gPrikey)
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
	if sig.pi < 0 || sig.pi > p.n
		return false
	
	if sig.signature == nil
		return false
	
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

