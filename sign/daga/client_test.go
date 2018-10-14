package daga

import (
	"github.com/dedis/kyber"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var suite = NewSuiteEC()

// FIXME review/see if the test are sound and were correctly written
func TestNewClient(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(suite.RandomStream())
	client, err := NewClient(suite, i, s)
	assert.NoError(t, err, "Cannot initialize a new client with a given private key")
	assert.Equal(t, i, client.Index(), "Cannot initialize a new client with a given private key, wrong index")
	assert.True(t, client.PrivateKey().Equal(s), "Cannot initialize a new client with a given private key, wrong key")

	client, err = NewClient(suite, i, nil)
	assert.NoError(t, err, "Cannot create a new client without a private key")

	//Invalid input
	client, err = NewClient(suite, -2, s)
	assert.Error(t, err, "Wrong check: Invalid index")
}

func TestNewInitialTagAndCommitments(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// normal execution
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	T0, S := tagAndCommitments.t0, tagAndCommitments.sCommits
	assert.NotNil(t, T0, "T0 nil")
	assert.NotNil(t, S, "sCommits nil")
	assert.NotNil(t, s, "s nil")
	assert.False(t, T0.Equal(suite.Point().Null()), "T0 is the null point")
	assert.Equal(t, len(S), len(servers)+2, "S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	for i, temp := range S {
		assert.False(t, temp.Equal(suite.Point().Null()), "Null point in sCommits at position %d", i)
	}
}

// test helper that sign returns a Challenge by signing the cs using the keys of the servers
func signDummyChallenge(cs kyber.Scalar, servers []Server) Challenge {
	msg, _ := cs.MarshalBinary()
	var sigs []serverSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, _ := SchnorrSign(suite, server.PrivateKey(), msg)
		sigs = append(sigs, serverSignature{index: server.Index(), sig: sig})
	}
	return Challenge{cs: cs, sigs: sigs}
}

// test helper that returns dummy channels to act as a dummy server/verifier
// that send challenge on pullChallenge channel upon reception of the prover's commitments on pullChallenge channel
func newDummyServerChannels(challenge Challenge) (chan []kyber.Point, chan Challenge) {
	// dummy channel to receive the commitments (they will be part of the returned proof)
	// and dummy channel to send a dummy challenge as we are only interested in the commitments
	// "push"/"pull" from the perspective of newClientProof()
	pushCommitments := make(chan []kyber.Point)
	pullChallenge := make(chan Challenge)
	go func() {
		<-pushCommitments
		pullChallenge <- challenge
	}()
	return pushCommitments, pullChallenge
}

func TestNewClientProof(t *testing.T) {
	// setup, test context, clients, servers
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	// normal execution, create client proof
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, err := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	assert.NoError(t, err, "newClientProof returned an error on valid inputs")
	commits, responses, subChallenges := proof.t, proof.r, proof.c
	// FIXME not sure whether these tests are pertinent or well written... they are testing the proof framework...not my code
	assert.Equal(t, len(commits), 3*len(clients))
	assert.Equal(t, len(subChallenges), len(clients))
	assert.Equal(t, len(responses), 2*len(clients))

	//Incorrect challenges
	var fake kyber.Scalar
	for {
		fake = suite.Scalar().Pick(suite.RandomStream())
		if !fake.Equal(cs) {
			break
		}
	}
	invalidChallenge := Challenge{cs: fake, sigs: validChallenge.sigs}
	pushCommitments, pullChallenge = newDummyServerChannels(invalidChallenge)
	proof, err = newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	commits, responses, subChallenges = proof.t, proof.r, proof.c
	assert.Error(t, err, "newClientProof returned no error on invalid server inputs (altered challenge)")
	assert.Equal(t, clientProof{}, proof, "proof not \"zero\" on error")

	//Signature modification
	newsig := append(validChallenge.sigs[0].sig, []byte("A")...)
	newsig = newsig[1:]
	wrongSigs := make([]serverSignature, len(validChallenge.sigs))
	copy(wrongSigs, validChallenge.sigs)
	wrongSigs[0].sig = newsig
	invalidChallenge = Challenge{cs: cs, sigs: wrongSigs}
	pushCommitments, pullChallenge = newDummyServerChannels(invalidChallenge)

	proof, err = newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	commits, responses, subChallenges = proof.t, proof.r, proof.c
	assert.Error(t, err, "newClientProof returned no error on invalid server inputs (altered signature)")
	assert.Equal(t, clientProof{}, proof, "proof not \"zero\" on error")
}

func TestVerifyClientProof(t *testing.T) {
	// TODO maybe assemble a message using previous student code and verify with current code (but that would amount to testing the proof package)
	// setup, test context, clients, servers
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	// create valid proof and auth. message
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, _ := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)

	clientMsg := AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Normal execution
	assert.NoError(t, validateClientMessage(suite, clientMsg), "Cannot validate valid client message")
	assert.NoError(t, verifyAuthenticationMessage(suite, clientMsg), "Cannot verify valid client proof")

	//Modify the value of some commitments
	scratchMsg := clientMsg
	i := rand.Intn(len(clients))
	ttemp := scratchMsg.p0.t[3*i].Clone()
	scratchMsg.p0.t[3*i] = suite.Point().Null()
	assert.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i)

	scratchMsg.p0.t[3*i] = ttemp.Clone()
	ttemp = scratchMsg.p0.t[3*i+1].Clone()
	scratchMsg.p0.t[3*i+1] = suite.Point().Null()
	assert.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i+1)

	scratchMsg.p0.t[3*i+1] = ttemp.Clone()
	ttemp = scratchMsg.p0.t[3*i+2].Clone()
	scratchMsg.p0.t[3*i+2] = suite.Point().Null()
	assert.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i+2)

	scratchMsg.p0.t[3*i+2] = ttemp.Clone()

	//tamper the challenge
	scratchMsg.p0.cs = suite.Scalar().Zero()
	assert.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of the challenge")
}

func TestGetFinalLinkageTag(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0 // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, _ := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Create the initial server message
	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, context, &servMsg, servers[i])
		assert.NoError(t, err, "server %v returned an error while processing valid auth. request", i)
	}

	//Normal execution for a normal client
	Tf, err := GetFinalLinkageTag(suite, context, servMsg)
	assert.NoError(t, err, "Cannot extract final linkage tag")
	assert.NotNil(t, Tf, "Cannot extract final linkage tag")

	//Empty inputs
	Tf, err = GetFinalLinkageTag(suite, nil, servMsg)
	assert.Error(t, err, "wrong check: Empty context")
	assert.Nil(t, Tf, "wrong check: Empty context")

	Tf, err = GetFinalLinkageTag(suite, context, ServerMessage{})
	assert.Error(t, err, "wrong check: Empty context")
	assert.Nil(t, Tf, "wrong check: Empty context")

	//Change a signature
	servMsg.sigs[0].sig = append(servMsg.sigs[0].sig[1:], servMsg.sigs[0].sig[0])
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	assert.Error(t, err, "Invalid signature accepted")
	assert.Nil(t, Tf, "Invalid signature accepted")

	//Revert the change
	servMsg.sigs[0].sig = append([]byte{0x0}, servMsg.sigs[0].sig...)
	servMsg.sigs[0].sig[0] = servMsg.sigs[0].sig[len(servMsg.sigs[0].sig)-1]
	servMsg.sigs[0].sig = servMsg.sigs[0].sig[:len(servMsg.sigs[0].sig)-2]

	//Misbehaving clients
	// TODO add mutliple different scenarios
	clients, servers, context, _ = GenerateTestContext(suite, rand.Intn(10)+2, 1)
	tagAndCommitments, s = newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	// 1 server, bad tagAndCommitments, invalid proof => reject proof => cannot get (even try to get) final tag
	S := tagAndCommitments.sCommits

	S[2] = suite.Point().Null()
	validChallenge = signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage = AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		request: clientMessage,
		proofs:  nil,
		tags:    nil,
		sigs:    nil,
		indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, context, &servMsg, servers[i])
		assert.Error(t, err, "server %v returned no error while processing invalid auth. request", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	assert.Error(t, err, "can extract final linkage tag for an invalid request, should have returned an error")
	assert.Nil(t, Tf, "Tf not nil on error")
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 1 server, bad tagAndCommitments, valid proof => flag as misbehaving => receive null final tag
	//Assemble the client message
	S = tagAndCommitments.sCommits
	S[2] = suite.Point().Null()
	tagAndCommitments.t0.Set(suite.Point().Null())
	validChallenge = signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, *context, clients[0], *tagAndCommitments, suite.Scalar().Zero(), pushCommitments, pullChallenge)
	clientMessage = AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		request: clientMessage,
		proofs:  nil,
		tags:    nil,
		sigs:    nil,
		indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, context, &servMsg, servers[i])
		assert.NoError(t, err, "server %v returned an error while processing auth. request of a misbehaving client", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	assert.NoError(t, err, "cannot extract final linkage tag for a misbehaving client")
	assert.True(t, Tf.Equal(suite.Point().Null()), "Tf not Null for a misbehaving client")

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// n>1 servers, bad tagAndCommitments, valid proof => flag as misbehaving => receive null final tag
	clients, servers, context, _ = GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)
	//Assemble the client message
	tagAndCommitments, s = newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	S = tagAndCommitments.sCommits
	S[2] = suite.Point().Null()
	validChallenge = signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage = AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		request: clientMessage,
		proofs:  nil,
		tags:    nil,
		sigs:    nil,
		indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, context, &servMsg, servers[i])
		assert.NoError(t, err, "server %v returned an error while processing auth. request of a misbehaving client", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	assert.NoError(t, err, "cannot extract final linkage tag for a misbehaving client")
	assert.True(t, Tf.Equal(suite.Point().Null()), "Tf not Null for a misbehaving client")
}

// TODO merge or rearrange with some tests above as lots of things are redundant...or should belong to same test
// e.g see testverifyclientproof and its tampering of the p0.commitments
// + fundamentaly verify message => verify proof, so either split accordingly and test only message related things reps. proof related things in both
// or merge them together in same test and test everything
// or (but I won't lose more time on this) rewrite everything to follow best testing practises (more better named small tests for a start)
func TestValidateClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, _ := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Normal execution
	// TODO already tested somewhere above...
	assert.NoError(t, verifyAuthenticationMessage(suite, clientMessage), "Cannot verify valid client proof")

	//Modifying the length of various elements
	ScratchMsg := clientMessage
	ScratchMsg.p0.c = append(ScratchMsg.p0.c, suite.Scalar().Pick(suite.RandomStream()))
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.c = ScratchMsg.p0.c[:len(clients)-1]
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.p0.r = append(ScratchMsg.p0.r, suite.Scalar().Pick(suite.RandomStream()))
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.r = ScratchMsg.p0.r[:2*len(clients)-1]
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.p0.t = append(ScratchMsg.p0.t, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.t = ScratchMsg.p0.t[:3*len(clients)-1]
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.sCommits = append(ScratchMsg.sCommits, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.sCommits), len(servers)+2)

	ScratchMsg.sCommits = ScratchMsg.sCommits[:len(servers)+1]
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.sCommits), len(servers)+2)

	//Modify the value of the generator in S[1]
	ScratchMsg = clientMessage
	ScratchMsg.sCommits[1] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect check for the generator in S[1]")

	ScratchMsg.sCommits[1] = suite.Point().Mul(suite.Scalar().One(), nil)

	//Remove T0
	ScratchMsg.t0 = nil
	assert.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Accepts a empty T0")
}

func TestToBytes_ClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0  // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, _ := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := AuthenticationMessage{
		c:                        *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:                       proof,
	}

	//Normal execution
	data, err := clientMessage.ToBytes()
	assert.NoError(t, err, "Cannot convert valid Client Message to bytes")
	assert.NotNil(t, data, "Data is empty for a correct Client Message")
}

func TestToBytes_ClientProof(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test client proof
	tagAndCommitments, s := newInitialTagAndCommitments(suite, context.g.y, context.h[clients[0].Index()])
	proof, _ := newClientProof(suite, *context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)

	//Normal execution
	data, err := proof.ToBytes()
	assert.NoError(t, err, "Cannot convert valid proof to bytes")
	assert.NotNil(t, data, "Data is empty for a correct proof")
}
