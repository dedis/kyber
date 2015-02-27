package promise

import (
	"github.com/dedis/crypto/abstract"
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
 */
func (p *Promise) Init(priKey abstract.Secret, sgroup abstract.Group, t, r int,
	guardians []abstract.Point) *Promise {

	n := len(p.guardians)

	// Basic initialization
	p.t          = t
	p.r          = r
	p.shareGroup = sgroup
	p.guardians  = guardians
	p.secrets    = make([]abstract.Point, n, n)
	p.signatures = make([][]byte, n, n)

	// Verify that t <= r <= n
	if n < t {
		panic("Not enough guardians for the secret")
	} 
	if r < t {
		p.r = t
	}
	if r > n {
		p.r = n
	}

	// Create the public polynomial and private shares. The total shares made
	// should be equal to teh number of guardians while the minimum shares
	// needed to reconstruct should be t.
	pripoly   := new(poly.PriPoly).Pick(p.shareGroup, p.t, priKey, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, n)
	p.pubPoly = new(poly.PubPoly).Commit(pripoly, nil)
	
	// Populate the secrets array. It encrypts each share with a diffie
	// hellman exchange between the originator of the promist and the
	// specific guardian.
	for i := 0 ; i < n; i++ {
		diffie := p.shareGroup.Point().Mul(guardians[i], priKey)
		p.secrets[i] = p.shareGroup.Point().Mul(diffie, prishares.Share(i))
	}
	
	return p
}


