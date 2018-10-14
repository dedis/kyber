package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"strconv"
)

type Client interface {
	PublicKey() kyber.Point
	PrivateKey() kyber.Scalar
	Index() int
}

type client struct {
	key key.Pair
	index int
}

func (c client) PublicKey() kyber.Point {
	return c.key.Public
}

func (c client) PrivateKey() kyber.Scalar {
	return c.key.Private
}

func (c client) Index() int {
	return c.index
}

func NewClient(suite Suite, i int, s kyber.Scalar) (Client, error) {
	if i < 0 {
		return nil, errors.New("invalid parameters, negative index")
	}

	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		// FIXME check if s is a proper secret (see small subgroup attacks on some groups/curves).
		// FIXME .. or remove this option
		// FIXME .. or make it a proper secret..
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}

	return client{
		index: i,
		key:   *kp,
	}, nil
}

// authenticationMessage stores an authentication message request (M0)
// sent by a client to an arbitrarily chosen server (listed in the context).
//
// Upon receiving the client’s message, all servers collectively process M0
// and either accept or reject the client's authentication request.
//
// c holds the authenticationContext used by the client to authenticate.
//
// initialTagAndCommitments contains the client's commitments to the secrets shared with all the servers
// and the client's initial linkage tag (see initialTagAndCommitments).
//
// p0 is the client's proof that he correctly followed the protocol and
// that he belongs to the authorized clients in the context. (see clientProof).
type AuthenticationMessage struct {
	c AuthenticationContext
	initialTagAndCommitments  // FIXME try to make it private
	p0 clientProof
}

func NewAuthenticationMessage(suite Suite, context AuthenticationContext, client Client,
	pushCommitments chan<- []kyber.Point,
	pullChallenge <-chan Challenge) (*AuthenticationMessage, error) {
	// TODO see if context big enough to justify transforming the parameter into *authenticationContext
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// DAGA client Steps 1, 2, 3:
	TAndS, s := newInitialTagAndCommitments(suite, context.g.y, context.h[client.Index()])

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PKclient, with one random server
	if P, err := newClientProof(suite, context, client, *TAndS, s, pushCommitments, pullChallenge); err != nil {
		// TODO log QUESTION can I have an intro on the logging practises at DEDIS
		return nil, err
	} else {
		// DAGA client Step 5
		M0 := AuthenticationMessage{
			c:                        context,
			initialTagAndCommitments: *TAndS,
			p0:                       P,
		}
		return &M0, nil
	}
}

// validateClientMessage is an utility function to validate that a client message is correctly formed
func validateClientMessage(suite Suite, msg AuthenticationMessage) error {
	// TODO rename validateAuthenticationMessage
	//Number of clients
	i := len(msg.c.g.x)
	//Number of servers
	j := len(msg.c.g.y)
	//A commitment for each server exists and the second element is the generator S=(Z,g,S1,..,Sj)
	if len(msg.sCommits) != j+2 {
		return fmt.Errorf("validateClientMessage: wrong number of commitments in sCommits (%d), expected: %d", len(msg.sCommits), j+2)
	}
	if !msg.sCommits[1].Equal(suite.Point().Base()) {
		return errors.New("validateClientMessage: second group element in sCommits is not the group generator")
	}
	//T0 not empty
	if msg.t0 == nil {
		return errors.New("validateClientMessage: initial tag T0 is nil")
	}
	//Proof fields have the correct size
	if len(msg.p0.c) != i || len(msg.p0.r) != 2*i || len(msg.p0.t) != 3*i || msg.p0.cs == nil {
		return fmt.Errorf("validateClientMessage: malformed clientProof, %v", msg.p0)
	}
	return nil
}

// Returns whether an authenticationMessage is valid or not, (well formed AND valid/accepted proof)
//
// msg the authenticationMessage to verify
func verifyAuthenticationMessage(suite Suite, msg AuthenticationMessage) error {
	if err := validateClientMessage(suite, msg); err != nil {
		return errors.New("verifyAuthenticationMessage:" + err.Error())
	}
	// TODO FIXME decide from where to pick the args when choice ! (from client msg or from server state ?)
	// FIXME here challenge ~~should~~ MUST be picked from server state IMO but QUESTION ask Ewa Syta !
	// TODO resolve all these when building the actual service
	if err := verifyClientProof(suite, msg.c, msg.p0, msg.initialTagAndCommitments); err != nil {
		return errors.New("verifyAuthenticationMessage:" + err.Error())
	}
	return nil
}

// initialTagAndCommitments stores :
//
// sCommits the client's commitments to the secrets shared with the servers.
// that is a set of commitments sCommits = { Z, S0, .., Sj, .., Sm } s.t.
// S0 = g, Sj = g^(∏sk : k=1..j) (see 4.3.5 client's protocol step 2-3).
//
// t0 the client's initial linkage tag. t0 = h^(∏sk : k=1..m)
//
// here above, (Z,z) is the client's ephemeral DH key pair, (see 4.3.5 client's protocol step 1)
// and sk=Hash1(Yk^z)
type initialTagAndCommitments struct {
	sCommits []kyber.Point
	t0       kyber.Point
}

// TODO later add logging where needed/desired
// TODO decide if better to make this function a method of client that accept context, or better add a method to client that use it internally
// Returns a pointer to a newly allocated initialTagAndCommitments struct correctly initialized
// and an opening s (product of all secrets that client shares with the servers) of Sm (that is needed later to build client's proof PKclient)
// (i.e. performs client protocol Steps 1,2 and 3)
//
// serverKeys the public keys of the servers (of a particular authenticationContext)
//
// clientGenerator the client's per-round generator
//
func newInitialTagAndCommitments(suite Suite, serverKeys []kyber.Point, clientGenerator kyber.Point) (*initialTagAndCommitments, kyber.Scalar) {
	// TODO parameter checking, what should we check ? assert that clientGenerator is indeed a generator of the group ?

	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private // FIXME how to erase ?
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, 0, len(serverKeys))
	for _, serverKey := range serverKeys {
		hasher := suite.Hash()
		// QUESTION ask Ewa Syta
		// can it be a problem if hash size = 256 > log(phi(group order = 2^252 + 27742317777372353535851937790883648493 prime))
		// because it is currently the case, to me seems that by having a hash size greater than the number of phi(group order)
		// it means that the resulting "pseudo random keys" will no longer have same uniform distribution since two keys can be = mod phi(group order).
		// (to my understanding secrets distribution will not be uniform and that kind of violate random oracle model assumption)
		// but since nothing is said about this concern in Curve25519 paper I'd say this is not an issue finally...
		suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		// QUESTION FIXME mask the bits to avoid small subgroup attacks
		// (but think how an attacker could obtain sP where P has small order.. maybe this is not possible and hence protection irrelevant,
		// anyway to my understanding we lose nothing (security-wise) by always performing the bittwiddlings and we might lose security if we don't !
		// relevant link/explanations https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati
		sharedSecrets = append(sharedSecrets, sharedSecret)
	} // QUESTION don't understand why sha3(sha512) was done by previous student instead of sha256 in the first place...? => I use only one hash (sha256 for now)

	//DAGA client Step 3: computes initial linkage tag and commitments to the shared secrets
	//	Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for _, sharedSecret := range sharedSecrets {
		exp.Mul(exp, sharedSecret)
	}
	T0 := suite.Point().Mul(exp, clientGenerator)

	//	Computes the commitments to the shared secrets
	S := make([]kyber.Point, 0, len(serverKeys)+2)
	S = append(S, Z, suite.Point().Base()) // Z, S0=g
	exp = sharedSecrets[0]                 // s1
	for _, sharedSecret := range sharedSecrets[1:] /*s2..sm*/ {
		S = append(S, suite.Point().Mul(exp, nil)) // S1..Sm-1
		exp.Mul(exp, sharedSecret)
	}
	S = append(S, suite.Point().Mul(exp, nil) /*Sm*/)
	s := exp

	return &initialTagAndCommitments{
		t0:       T0,
		sCommits: S,
	}, s
}

// GetFinalLinkageTag checks the server's signatures and proofs
// and outputs the final linkage tag or an error
func GetFinalLinkageTag(suite Suite, context *AuthenticationContext, msg ServerMessage) (Tf kyber.Point, err error) {
	// FIXME QUESTION not sure that the verifyserverproof belongs inside this method in the client..DAGA paper specify that it is the servers that check it
	// + not sure that this is how things were intended in the paper, maybe redefine what is sent to the client ! (only the final tag...) but why not... as it is now..
	// TODO but guess this won't do any harm, will need to decide when building the service

	//Input checks
	if context == nil || len(msg.tags) == 0 || len(msg.tags) != len(msg.proofs) || len(msg.proofs) != len(msg.sigs) || len(msg.sigs) != len(msg.indexes) {
		return nil, errors.New("invalid inputs")
	}

	data, e := msg.request.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in request: %s", e)
	}
	for i, p := range msg.proofs {
		//verify signatures
		temp, err := msg.tags[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error in tags: %s", err)
		}
		data = append(data, temp...)
		temp, err = p.ToBytes()
		if err != nil {
			return nil, fmt.Errorf("error in proofs: %s", err)
		}
		data = append(data, temp...)
		data = append(data, []byte(strconv.Itoa(msg.indexes[i]))...)
		err = SchnorrVerify(suite, context.g.y[msg.sigs[i].index], data, msg.sigs[i].sig)
		if err != nil {
			return nil, fmt.Errorf("error in signature: %d\n%s", i, err)
		}
		//verify proofs
		var valid bool
		if p.r2 == nil {
			valid = verifyMisbehavingProof(suite, context, i, &p, msg.request.sCommits[0])
		} else {
			valid = verifyServerProof(suite, context, i, &msg)
		}
		if !valid {
			return nil, errors.New("invalid server proof")
		}
	}
	return msg.tags[len(msg.tags)-1], nil
}