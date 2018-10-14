package daga

// FIXME audit/verify + change receivers pointer => value where possible + rename "everything"

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"io"
	"strconv"
)

// TODO doc
type Server interface {
	Index() int
	RoundSecret() kyber.Scalar //Per round secret
	SetRoundSecret(scalar kyber.Scalar)
	PublicKey() kyber.Point
	PrivateKey() kyber.Scalar
}

type server struct {
	key   key.Pair
	index int
	r     kyber.Scalar //Per round secret
}

//CreateServer is used to initialize a new server with a given index
//If no private key is given, a random one is chosen
func NewServer(suite Suite, i int, s kyber.Scalar) (Server, error) {
	if i < 0 {
		return nil, fmt.Errorf("invalid parameters")
	}

	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		// FIXME check if s is a proper secret (see small subgroup attacks on some groups/curves)... or remove this option ..or make it a proper secret..
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}
	return &server{
		index: i,
		key:   *kp,
	}, nil
}

//returns the server's index
func (s server) Index() int {
	return s.index
}

//returns the public key of the server
func (s server) PublicKey() kyber.Point {
	return s.key.Public
}

//returns the private key of the server
func (s server) PrivateKey() kyber.Scalar {
	return s.key.Private
}

//returns the (current) per round secret of the server
func (s server) RoundSecret() kyber.Scalar {
	return s.r
}

//set the server's round secret to be secret
func (s *server) SetRoundSecret(secret kyber.Scalar) {
	s.r = secret
}

/*ServerMessage stores the message sent by a server to one or many others*/
type ServerMessage struct {
	request AuthenticationMessage
	tags    []kyber.Point
	proofs  []serverProof
	indexes []int
	sigs    []serverSignature
}

/*Commitment stores the index of the server, the commitment value and the signature for the commitment*/
type Commitment struct {
	commit kyber.Point
	serverSignature
}

/*serverSignature stores a signature created by a server and the server's index*/
type serverSignature struct {
	index int
	sig   []byte
}

/*ChallengeCheck stores all the information passed along the servers to check and sign the challenge*/
type ChallengeCheck struct {
	cs       kyber.Scalar
	sigs     []serverSignature //Signatures for cs only
	commits  []Commitment
	openings []kyber.Scalar
}

/*serverProof stores a server proof of his computations*/
type serverProof struct {
	t1 kyber.Point
	t2 kyber.Point
	t3 kyber.Point
	c  kyber.Scalar
	r1 kyber.Scalar
	r2 kyber.Scalar
}

/*GenerateCommitment creates the server's commitment and its opening for the distributed challenge generation*/
func GenerateCommitment(suite Suite, context *AuthenticationContext, server Server) (commit *Commitment, opening kyber.Scalar, err error) {
	// TODO rename
	opening = suite.Scalar().Pick(suite.RandomStream())
	com := suite.Point().Mul(opening, nil)
	msg, err := com.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("error in conversion of commit: %s", err)
	}
	sig, err := SchnorrSign(suite, server.PrivateKey(), msg)
	if err != nil {
		return nil, nil, fmt.Errorf("error in commit signature generation: %s", err)
	}
	return &Commitment{serverSignature: serverSignature{index: server.Index(), sig: sig}, commit: com}, opening, nil
}

/*VerifyCommitmentSignature verifies that all the commitments are valid and correctly signed*/
func VerifyCommitmentSignature(suite Suite, context *AuthenticationContext, commits []Commitment) (err error) {
	for i, com := range commits {
		if i != com.index {
			return fmt.Errorf("wrong index: got %d expected %d", com.index, i)
		}
		// QUESTION FIXME: How to check that a point is on the curve? (don't remember why but the answer is you don't need if you use edwards curve25519)
		// FIXME but still this is a valid concern since if we change the curve/suite_implementation we would like the code to remain correct or ?

		//Convert the commitment and verify the signature
		msg, e := com.commit.MarshalBinary()
		if e != nil {
			return fmt.Errorf("error in conversion of commit for verification: %s", err)
		}
		err = SchnorrVerify(suite, context.g.y[i], msg, com.sig)
		if err != nil {
			return err
		}
	}
	return nil
}

/*CheckOpenings verifies each opening and returns the computed master challenge*/
func checkOpenings(suite Suite, context *AuthenticationContext, commits []Commitment, openings []kyber.Scalar) (cs kyber.Scalar, err error) {
	// FIXME rename or split in 2
	if context == nil {
		return nil, fmt.Errorf("empty context")
	}
	if len(commits) != len(context.g.y) {
		return nil, fmt.Errorf("incorrect number of commits: got %d expected %d", len(commits), len(context.g.y))
	}
	if len(openings) != len(context.g.y) {
		return nil, fmt.Errorf("incorrect number of openings: got %d expected %d", len(openings), len(context.g.y))
	}

	cs = suite.Scalar().Zero()
	for i := 0; i < len(commits); i++ {
		c := suite.Point().Mul(openings[i], nil)
		if !commits[i].commit.Equal(c) {
			return nil, fmt.Errorf("mismatch opening for server %d", i)
		}
		cs = suite.Scalar().Add(cs, openings[i])
	}
	return cs, nil
}

/*InitializeChallenge creates a Challenge structure from a challenge value
It checks the openings before doing so*/
func InitializeChallenge(suite Suite, context *AuthenticationContext, commits []Commitment, openings []kyber.Scalar) (*ChallengeCheck, error) {
	if context == nil || len(commits) == 0 || len(commits) != len(openings) {
		return nil, fmt.Errorf("invalid inputs")
	}
	cs, err := checkOpenings(suite, context, commits, openings)
	if err != nil {
		return nil, err
	}

	return &ChallengeCheck{cs: cs, commits: commits, openings: openings, sigs: nil}, nil
}

/*CheckUpdateChallenge verifies that all the previous servers computed the same challenges and that their signatures are valid
It also adds the server's signature to the list if the round-robin is not completed (the challenge has not yet made it back to the leader)
It must be used after the leader ran InitializeChallenge and after each server received the challenge from the previous server*/
func CheckUpdateChallenge(suite Suite, context *AuthenticationContext, challenge *ChallengeCheck, server Server) error {
	//Check the signatures and check for duplicates
	msg, e := challenge.cs.MarshalBinary()
	if e != nil {
		return fmt.Errorf("error in challenge conversion: %s", e)
	}
	encountered := map[int]bool{}
	for _, sig := range challenge.sigs {
		if encountered[sig.index] == true {
			return fmt.Errorf("duplicate signature")
		}
		encountered[sig.index] = true

		e = SchnorrVerify(suite, context.g.y[sig.index], msg, sig.sig)
		if e != nil {
			return fmt.Errorf("%s", e)
		}
	}

	//Checks the signatures of the commitments
	err := VerifyCommitmentSignature(suite, context, challenge.commits)
	if err != nil {
		return err
	}
	//Checks the openings
	cs, err := checkOpenings(suite, context, challenge.commits, challenge.openings)
	if err != nil {
		return err
	}
	//Checks that the challenge values match
	if !cs.Equal(challenge.cs) {
		return fmt.Errorf("challenge values does not match")
	}

	//Add the server's signature to the list if it is not the last one
	if len(challenge.sigs) == len(context.g.y) {
		return nil
	}
	sig, e := SchnorrSign(suite, server.PrivateKey(), msg)
	if e != nil {
		return e
	}
	challenge.sigs = append(challenge.sigs, serverSignature{index: server.Index(), sig: sig})

	return nil
}

/*FinalizeChallenge is used to convert the data passed between the servers into the challenge sent to the client
It must be used after the leader got the message back and ran CheckUpdateChallenge*/
func FinalizeChallenge(context *AuthenticationContext, challenge *ChallengeCheck) (Challenge, error) {
	if context == nil || challenge == nil {
		return Challenge{}, fmt.Errorf("invalid inputs")
	}
	if len(challenge.sigs) != len(context.g.y) {
		return Challenge{}, fmt.Errorf("signature count does not match: got %d expected %d", len(challenge.sigs), len(context.g.y))
	}

	return Challenge{cs: challenge.cs, sigs: challenge.sigs}, nil
}

//InitializeServerMessage creates a ServerMessage from a ClientMessage to ease further processing
// FIXME QUESTION rename .. New..
func InitializeServerMessage(request *AuthenticationMessage) (msg *ServerMessage, err error) {
	if request == nil {
		return nil, errors.New("InitializeServerMessage: request is nil")
	}
	return &ServerMessage{
		request: *request,
		tags:    nil,
		indexes: nil,
		proofs:  nil,
		sigs:    nil,
	}, nil
}

/*ServerProtocol runs the server part of DAGA upon receiving a message from either a server or a client*/
// TODO DRY see what can be shared with GetFinalLinkageTag ...
func ServerProtocol(suite Suite, context *AuthenticationContext, msg *ServerMessage, server Server) error {
	// input checks
	if context == nil || msg == nil || len(msg.indexes) != len(msg.proofs) || len(msg.proofs) != len(msg.tags) || len(msg.tags) != len(msg.sigs) {
		return fmt.Errorf("invalid message")
	}

	//Step 1
	//Verify that the client's message is correctly formed and its proof correct
	if err := verifyAuthenticationMessage(suite, msg.request); err != nil {
		return errors.New("ServerProtocol: malformed client message or wrong proof")
	}

	//Checks that not all servers already did the protocol
	if len(msg.indexes) >= len(context.g.y) {
		return fmt.Errorf("ServerProtocol: too many calls of the protocol") //... ok... smells like fish..
	}

	// Iteratively checks each signature if this is not the first server to receive the client's request
	data, e := msg.request.ToBytes()
	if e != nil {
		return errors.New("ServerProtocol: failed to marshall client's msg, " + e.Error())
	}
	if len(msg.indexes) != 0 {
		for i := 0; i < len(msg.indexes); i++ {
			temp, err := msg.tags[i].MarshalBinary()
			if err != nil {
				return errors.New("ServerProtocol: failed to marshall tags, " + err.Error())
			}
			data = append(data, temp...)

			temp, err = msg.proofs[i].ToBytes()
			if err != nil {
				return fmt.Errorf("error in proofs: %s", err)
			}
			data = append(data, temp...)

			data = append(data, []byte(strconv.Itoa(msg.indexes[i]))...)

			err = SchnorrVerify(suite, context.g.y[msg.sigs[i].index], data, msg.sigs[i].sig)
			if err != nil {
				return fmt.Errorf("error in signature: "+strconv.Itoa(i)+"\n%s", err)
			}
		}
	}

	//Check all the proofs
	if len(msg.proofs) != 0 {
		for i, p := range msg.proofs {
			var valid bool
			if p.r2 == nil {
				valid = verifyMisbehavingProof(suite, context, i, &p, msg.request.sCommits[0])
			} else {
				valid = verifyServerProof(suite, context, i, msg)
			}
			if !valid {
				return fmt.Errorf("invalid server proof")
			}
		}
	}

	//Step 2: Verify the correct behaviour of the client
	hasher := suite.Hash()
	suite.Point().Mul(server.PrivateKey(), msg.request.sCommits[0]).MarshalTo(hasher)
	s := suite.Scalar().SetBytes(hasher.Sum(nil))
	var T kyber.Point
	var proof *serverProof
	//Detect a misbehaving client and generate the elements of the server's message accordingly
	if !msg.request.sCommits[server.Index()+2].Equal(suite.Point().Mul(s, msg.request.sCommits[server.Index()+1])) {
		T = suite.Point().Null()
		proof, e = generateMisbehavingProof(suite, context, msg.request.sCommits[0], server)
	} else {
		inv := suite.Scalar().Inv(s)
		exp := suite.Scalar().Mul(server.RoundSecret(), inv)
		if len(msg.tags) == 0 {
			T = suite.Point().Mul(exp, msg.request.t0)
		} else {
			T = suite.Point().Mul(exp, msg.tags[len(msg.tags)-1])
		}
		proof, e = generateServerProof(suite, context, s, T, msg, server)
	}
	if e != nil {
		return e
	}

	//Signs our message
	temp, e := T.MarshalBinary()
	if e != nil {
		return fmt.Errorf("error in T: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.ToBytes()
	if e != nil {
		return fmt.Errorf("error in proof: %s", e)
	}
	data = append(data, temp...)

	data = append(data, []byte(strconv.Itoa(server.Index()))...)

	sign, e := SchnorrSign(suite, server.PrivateKey(), data)
	if e != nil {
		return fmt.Errorf("error in own signature: %s", e)
	}

	signature := serverSignature{sig: sign, index: server.Index()}

	//Step 4: Form the new message
	msg.tags = append(msg.tags, T)
	msg.proofs = append(msg.proofs, *proof)
	msg.indexes = append(msg.indexes, server.Index())
	msg.sigs = append(msg.sigs, signature)

	return nil
}

/*generateServerProof creates the server proof for its computations*/
func generateServerProof(suite Suite, context *AuthenticationContext, s kyber.Scalar, T kyber.Point, msg *ServerMessage, server Server) (proof *serverProof, err error) {
	//Input validation
	if context == nil {
		return nil, fmt.Errorf("empty context")
	}
	if s == nil {
		return nil, fmt.Errorf("empty s")
	}
	if T == nil {
		return nil, fmt.Errorf("empty T")
	}
	if msg == nil {
		return nil, fmt.Errorf("empty server message")
	}

	//Step 1
	v1 := suite.Scalar().Pick(suite.RandomStream())
	v2 := suite.Scalar().Pick(suite.RandomStream())

	var a kyber.Point
	if len(msg.tags) == 0 {
		a = suite.Point().Mul(v1, msg.request.t0)
	} else {
		a = suite.Point().Mul(v1, msg.tags[len(msg.tags)-1])
	}

	//exp := suite.Scalar().Neg(v2)
	b := suite.Point().Mul(v2, T)
	t1 := suite.Point().Sub(a, b)

	t2 := suite.Point().Mul(v1, nil)

	t3 := suite.Point().Mul(v2, msg.request.sCommits[server.Index()+1]) //Accesses S[j-1]

	//Step 2
	var Tprevious kyber.Point
	if len(msg.tags) == 0 {
		Tprevious = msg.request.t0
	} else {
		Tprevious = msg.tags[len(msg.tags)-1]
	}
	//Generating the hash
	hasher := suite.Hash()
	Tprevious.MarshalTo(hasher)
	T.MarshalTo(hasher)
	context.r[server.Index()].MarshalTo(hasher)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(hasher)
	msg.request.sCommits[server.Index()+2].MarshalTo(hasher)
	msg.request.sCommits[server.Index()+1].MarshalTo(hasher)
	t1.MarshalTo(hasher)
	t2.MarshalTo(hasher)
	t3.MarshalTo(hasher)
	challenge := hasher.Sum(nil)
	c := suite.Scalar().SetBytes(challenge)
	//rand := suite.Cipher(challenge)
	//c := suite.Scalar().Pick(rand)
	//Step 3
	d := suite.Scalar().Mul(c, server.RoundSecret())
	r1 := suite.Scalar().Sub(v1, d)

	e := suite.Scalar().Mul(c, s)
	r2 := suite.Scalar().Sub(v2, e)

	//Step 4
	return &serverProof{
		t1: t1,
		t2: t2,
		t3: t3,
		c:  c,
		r1: r1,
		r2: r2,
	}, nil
}

/*verifyServerProof verifies a server proof*/
func verifyServerProof(suite Suite, context *AuthenticationContext, i int, msg *ServerMessage) bool {
	//Input checks
	if context == nil || msg == nil {
		return false
	}

	if i >= len(msg.proofs) || i < 0 {
		return false
	}

	//Verify format of the proof
	if msg.proofs[i].c == nil || msg.proofs[i].t1 == nil || msg.proofs[i].t2 == nil || msg.proofs[i].t3 == nil || msg.proofs[i].r1 == nil || msg.proofs[i].r2 == nil {
		return false
	}

	index := msg.indexes[i]

	//Step 1
	var a kyber.Point
	if i == 0 {
		a = suite.Point().Mul(msg.proofs[i].r1, msg.request.t0)
	} else {
		a = suite.Point().Mul(msg.proofs[i].r1, msg.tags[i-1])
	}
	//exp := suite.Scalar().Neg(msg.proofs[i].r2)
	b := suite.Point().Mul(msg.proofs[i].r2, msg.tags[i])
	t1 := suite.Point().Sub(a, b)

	d := suite.Point().Mul(msg.proofs[i].r1, nil)
	e := suite.Point().Mul(msg.proofs[i].c, context.r[index])
	t2 := suite.Point().Add(d, e)

	f := suite.Point().Mul(msg.proofs[i].r2, msg.request.sCommits[index+1])
	g := suite.Point().Mul(msg.proofs[i].c, msg.request.sCommits[index+2])
	t3 := suite.Point().Add(f, g)

	//Step 2
	var Tprevious kyber.Point
	if i == 0 {
		Tprevious = msg.request.t0
	} else {
		Tprevious = msg.tags[i-1]
	}
	// FIXME remember to use hashtwo when/where needed to keep things compatible with other implementations
	hasher := suite.Hash()
	Tprevious.MarshalTo(hasher)
	msg.tags[i].MarshalTo(hasher)
	context.r[index].MarshalTo(hasher)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(hasher)
	msg.request.sCommits[index+2].MarshalTo(hasher)
	msg.request.sCommits[index+1].MarshalTo(hasher)
	t1.MarshalTo(hasher)
	t2.MarshalTo(hasher)
	t3.MarshalTo(hasher)
	challenge := hasher.Sum(nil)

	c := suite.Scalar().SetBytes(challenge)

	if !c.Equal(msg.proofs[i].c) {
		return false
	}

	return true
}

/*generateMisbehavingProof creates the proof of a misbehaving client*/ // QUESTION server ? purpose of comment ?
func generateMisbehavingProof(suite Suite, context *AuthenticationContext, Z kyber.Point, server Server) (proof *serverProof, err error) {
	//Input checks
	if context == nil {
		return nil, fmt.Errorf("empty context")
	}
	if Z == nil {
		return nil, fmt.Errorf("empty Z")
	}

	Zs := suite.Point().Mul(server.PrivateKey(), Z)

	//Step 1
	v := suite.Scalar().Pick(suite.RandomStream())
	t1 := suite.Point().Mul(v, Z)
	t2 := suite.Point().Mul(v, nil)

	//Step 2
	hasher := sha512.New()
	var writer io.Writer = hasher
	Zs.MarshalTo(writer)
	Z.MarshalTo(writer)
	context.g.y[server.Index()].MarshalTo(writer)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(writer)
	t1.MarshalTo(writer)
	t2.MarshalTo(writer)
	challenge := hasher.Sum(nil)

	hasher = suite.Hash()
	hasher.Write(challenge)
	//rand := suite.Cipher(challenge)
	c := suite.Scalar().SetBytes(hasher.Sum(nil))

	//Step 3
	a := suite.Scalar().Mul(c, server.PrivateKey())
	r := suite.Scalar().Sub(v, a)

	//Step 4
	return &serverProof{
		t1: t1,
		t2: t2,
		t3: Zs,
		c:  c,
		r1: r,
		r2: nil,
	}, nil
}

/*verifyMisbehavingProof verifies a proof of a misbehaving client*/ // QUESTION server ? ..
func verifyMisbehavingProof(suite Suite, context *AuthenticationContext, i int, proof *serverProof, Z kyber.Point) bool {
	//Input checks
	if context == nil || proof == nil || Z == nil {
		return false
	}

	if i < 0 || i >= len(context.g.y) {
		return false
	}

	//Check that this is a misbehaving proof
	if proof.r2 != nil {
		return false
	}

	//Verify format of the proof
	if proof.t1 == nil || proof.t2 == nil || proof.t3 == nil || proof.c == nil || proof.r1 == nil {
		return false
	}

	//Step 1
	a := suite.Point().Mul(proof.r1, Z)       //r1 = r
	b := suite.Point().Mul(proof.c, proof.t3) //t3 = Zs
	t1 := suite.Point().Add(a, b)

	d := suite.Point().Mul(proof.r1, nil) //r1 = r
	e := suite.Point().Mul(proof.c, context.g.y[i])
	t2 := suite.Point().Add(d, e)

	//Step 2
	hasher := sha512.New()
	var writer io.Writer = hasher
	proof.t3.MarshalTo(writer)
	Z.MarshalTo(writer)
	context.g.y[i].MarshalTo(writer)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(writer)
	t1.MarshalTo(writer)
	t2.MarshalTo(writer)
	challenge := hasher.Sum(nil)

	hasher = suite.Hash()
	hasher.Write(challenge)

	//rand := suite.Cipher(challhasenge)
	c := suite.Scalar().SetBytes(hasher.Sum(nil))

	if !c.Equal(proof.c) {
		return false
	}
	return true
}

/*ToBytes is a helper function used to convert a ServerProof into []byte to be used in signatures*/
// QUESTION WTF ? + DRY there should be another way or no ?
func (proof serverProof) ToBytes() (data []byte, err error) {
	temp, e := proof.t1.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t1: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.t2.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t2: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.t3.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t3: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.c.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in c: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.r1.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in r1: %s", e)
	}
	data = append(data, temp...)

	//Need to test if r2 == nil (Misbehaving)
	if proof.r2 != nil {
		temp, e = proof.r2.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("error in r2: %s", e)
		}
		data = append(data, temp...)
	}

	return data, nil
}

/*GenerateNewRoundSecret creates a new secret for the server.
It returns the commitment to that secret to be included in the context and the new server*/
func GenerateNewRoundSecret(suite Suite, server Server) (kyber.Point, Server) {
	// FIXME rethink + instead store kp in server
	kp := key.NewKeyPair(suite)
	server.SetRoundSecret(kp.Private)
	return kp.Public, server
}
