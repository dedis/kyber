package promise

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
)

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
	// The cryptographic group to use for the private shares.
	shareGroup abstract.Group
	
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
	secrets    []abstract.Point
	
	// A list of signatures validating that a guardian has approved of the
	// secret share it is guarding.
	signatures [][]byte
}

/* Initializes a new promise to guard a secret.
 *
 * Arguments
 *    priKey   = the secret to be promised.
 *    sgroup   = the abstract group under which the shares will be constructed.
 *    t        = the minimum number of shares needed to reconstruct the secret.
 *    r        = the minimum signatures from guardians needed for the promise to
 *               be valid.
 *    guardians = a list of the public keys of servers to act as guardians.
 *
 * Returns
 *   The initialized promise
 */
func (p *Promise) Init(keyPair config.KeyPair, sgroup abstract.Group, t, r int,
	guardians []abstract.Point) *Promise {

	// Basic initialization
	p.t          = t
	p.r          = r
	p.n          = len(p.guardians)
	p.shareGroup = sgroup
	p.pubKey     = keyPair.Public
	p.guardians  = guardians
	p.secrets    = make([]abstract.Point, p.n , p.n )
	p.signatures = make([][]byte, p.n , p.n )

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
	pripoly   := new(poly.PriPoly).Pick(p.shareGroup, p.t, keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, p.n)
	p.pubPoly = new(poly.PubPoly).Commit(pripoly, nil)
	
	// Populate the secrets array. It encrypts each share with a diffie
	// hellman exchange between the originator of the promist and the
	// specific guardian.
	for i := 0 ; i < p.n; i++ {
		diffie := p.shareGroup.Point().Mul(guardians[i], keyPair.Secret)
		p.secrets[i] = p.shareGroup.Point().Mul(diffie, prishares.Share(i))
	}
	
	return p
}

/* Verify that a share has been properly constructed.
 *
 * Arguments
 *    i        = the index of the share to verify
 *    gPrikey  = the private key of the guardian of share i
 *
 * Return
 *   whether the decrypted secret properly passes the public polynomial.
 */
func (p *Promise) VerifyShare(i int, gPrikey abstract.Secret) bool {
	//diffie := p.shareGroup.Point().Mul(p.pubKey, gPrikey)	
	// TODO: actually figure out how to do decryption with diffie hellman.
	// just a placeholder for now.
	share := p.shareGroup.Secret()
	return p.pubPoly.Check(i, share)
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
	diffie := p.shareGroup.Point().Mul(p.pubKey, gPrikey)	
	// TODO: actually figure out how to do decryption with diffie hellman.
	// just a placeholder for now.
	share := p.shareGroup.Secret()

	return BlameProof{bi: i, bshare: share, diffieKey: diffie}
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

	// First, verify that the share given is actually the share the promiser
	// provided in the promise.
	badSecret := p.shareGroup.Point().Mul(proof.diffieKey, proof.bshare)
	if !badSecret.Equal(p.secrets[proof.bi]) {
		return false
	}

	// If so, see whether the bad share fails to pass pubPoly.Check. If it
	// fails, the blame is valid. If the check succeeds, the blame was
	// unjustified.
	return !p.pubPoly.Check(proof.bi, proof.bshare)
}

