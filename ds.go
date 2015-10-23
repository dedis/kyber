package main

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
)

// This file is an concrete example of how to generate a distrituted secret
// amongst peers using Verifiable Secret Sharing (Shamir secret sharing)

// The suite we are going to use
var suite = edwards.NewAES128SHA256Ed25519(true)

// how much peers
var n int = 3

// how much peers are needed to reconstruct the secret
var t int = 3

// the previous info in a struct
var threshold poly.Threshold = poly.Threshold{
	T: t,
	R: n,
	N: n,
}

// Some helpers function are below
// generateKeyPair will generate a random & fresh public / private key pair
func generateKeyPair() *config.KeyPair {
	keypair := new(config.KeyPair)
	keypair.Gen(suite, random.Stream)
	return keypair
}

// generateKeyPairList will generate N keypair
func generateKeyPairList(n int) []*config.KeyPair {
	l := make([]*config.KeyPair, n)
	for i := 0; i < n; i++ {
		l[i] = generateKeyPair()
	}
	return l
}

// Transforms a list of key pair into a list of only public keys
// That list is distributed amongst the peers
func generatePublicListFromPrivate(private []*config.KeyPair) []abstract.Point {
	l := make([]abstract.Point, len(private))
	for i := 0; i < len(private); i++ {
		l[i] = private[i].Public
	}
	return l
}

func main() {
	Joint()
	Schnorr2()
}

// First, let's generate the set of dealers and the set of receivers.
// A dealer create a secret and can distribute shares of its secret
// A receiver is one that receives such a share.
// A dealer create its shares and then encrypt each share for the respective
// receivers. In order to do that, a dealers need to know each public key of the
// receivers, so it can encrypt each share with the respective public key. That
// way, only the respective receiver can decrypt its own share.
// The joint.go library is designed such that the set of dealers and receivers
// can be completely disjoint. However, since the goal is to be able to
// reconstruct a secret from some shares, there is a mimimal threshold of share
// to have in order to reconstruct that secret. Therefore, the number of dealers
// must AT LEAST be equal to that threshold (info.T in our example)
func generateDealerReceiver(info poly.Threshold, ndeals, nreceivers int) ([]*poly.Deal, []*poly.Receiver) {
	// Generate the keys of the receivers
	receiverKeys := generateKeyPairList(nreceivers)
	// From it construct the list of the public keys that must be given to a
	// dealer
	receiverPublics := generatePublicListFromPrivate(receiverKeys)
	receivers := make([]*poly.Receiver, nreceivers)
	for i := 0; i < nreceivers; i++ {
		// Create a receiver by giving it the suite, the info about the
		// polynomials used and its private / public key
		receivers[i] = poly.NewReceiver(suite, info, receiverKeys[i])
	}
	dealers := make([]*poly.Deal, ndeals)
	for i := 0; i < ndeals; i++ {
		// Create a deal (holded by a dealer) with a fresh longterm, ephemereal
		// public /private key, the info, and the public keys of the receivers
		dealers[i] = new(poly.Deal).ConstructDeal(generateKeyPair(), generateKeyPair(), info.T, info.R, receiverPublics)
	}
	return dealers, receivers
}

func Joint() {
	deals, receivers := generateDealerReceiver(threshold, threshold.T, threshold.N)
	// make the exchange of shares by giving each deals to each receivers
	// for each receivers
	for i := 0; i < threshold.N; i++ {
		// give it each dealers
		for j := 0; j < threshold.T; j++ {
			// When you give a deal to a receiver, you must also give an index
			// so you can decrypt the share. A share is
			// simply a polynomial evaluated at a certain point F(i) = Si.
			// The deal encoded each share Si with the public key i in the array of the
			// public keys of the receivers.
			// The first return argument is a response, that indicates if the
			// share is good or not. Read deal.go for more details about this.
			// Note that this verification process is subject to future
			// refactoring and is not used for the moment.
			if _, err := receivers[i].AddDeal(i, deals[j]); err != nil {
				panic(fmt.Errorf("Could not add a deal %d to receiver %d\n", j, i))
			}

		}
	}

	// Now let's create the shared secret for every receivers. Every receivers
	// have a SharedSecret structure which is a public polynomial and a secret
	// share. The secret share is unique to every receivers and can be checked
	// against the public polynomial. The public polynomial is by definition the
	// same and represent the commitment to the shared secret.
	var sec *poly.SharedSecret
	for i := 0; i < threshold.N; i++ {
		if s, err := receivers[i].ProduceSharedSecret(); err != nil {
			panic(fmt.Errorf("Could not produce shared secret for receiver %d (secret : %v) : %v", i, s, err))
		} else {
			sec = s
		}
	}

	fmt.Printf("%+v", sec)
}

// Same as produceDealerReceiver except that it make the exchange of Dealer / Response
// Used in the schnorr example
func generateNMSetup(info poly.Threshold, ndeal, nrec int) ([]*poly.Deal, []*poly.Receiver) {
	dealers, receivers := generateDealerReceiver(info, ndeal, nrec)
	for i := 0; i < nrec; i++ {
		for j := 0; j < ndeal; j++ {
			_, err := receivers[i].AddDeal(i, dealers[j])
			if err != nil {
				panic(fmt.Sprintf("Could not AddDeal %d on Receiver %d!", j, i))
			}
		}
	}
	return dealers, receivers
}

// generateSharedSecret will return an array of SharedSecret structs
func generateSharedSecrets() []*poly.SharedSecret {
	_, rs := generateNMSetup(threshold, threshold.N, threshold.N)
	secrets := make([]*poly.SharedSecret, len(rs)) // len(rs) == n
	for i, _ := range rs {
		ss, err := rs[i].ProduceSharedSecret()
		if err != nil {
			panic(fmt.Sprintf("ProduceSharedSecret should not have behaved wrong : %v", err))
		}
		secrets[i] = ss
	}
	return secrets
}

// It will generate a long term array of schnorr structs
// it basically represents a peer in the protocol
func generateSchnorrStructs(info poly.Threshold) []*poly.Schnorr {
	longterms := generateSharedSecrets()
	schnorrs := make([]*poly.Schnorr, info.N)
	for i, _ := range longterms {
		schnorrs[i] = poly.NewSchnorr(suite, info, longterms[i])
	}
	return schnorrs
}

func Schnorr2() {
	var msg = suite.Hash()
	msg.Write([]byte("Hello World"))
	schnorrs := generateSchnorrStructs(threshold)

	randoms := generateSharedSecrets()
	for i, _ := range schnorrs {
		err := schnorrs[i].NewRound(randoms[i], msg)
		if err != nil {
			panic(fmt.Sprintf("NewRound should validate : %v", err))
		}
	}
	for i, _ := range schnorrs {
		ps := schnorrs[i].RevealPartialSig()
		// geive the partial sig to everyone
		for j, _ := range schnorrs {
			if err := schnorrs[j].AddPartialSig(ps); err != nil {
				panic(fmt.Sprintf("AddPartialSig should validate (adding partial sig of peer %d to peer %d : %v", ps.Index, schnorrs[j], err))
			}
		}
	}
	sig := make([]*poly.SchnorrSig, n)
	for i, _ := range schnorrs {
		s, err := schnorrs[i].Sig()
		if err != nil {
			panic(fmt.Sprintf("SchnorrSig should validate : %v", err))
		}
		sig[i] = s
	}
	// Verify the signature amongst each peers
	for i, _ := range schnorrs {
		err := schnorrs[i].VerifySchnorrSig(sig[0], msg)
		if err != nil {
			panic(fmt.Sprintf("VerifySchnorrSig on peer %d should validate the signature : %v", i, err))
		}
	}
}

// ExampleSChnorr shows a simple example of how to distributively sign something
func Schnorr1() {
	var msg = suite.Hash()
	msg.Write([]byte("Hello Distributed World\n"))
	// This will be the longterm distributed key used during the schnorr
	// signing. The process is the same as in the simple schnorr algo, first get
	// a longterm key, then get a random key then do the signature.
	longterms := generateSharedSecrets()

	// Create our array of schnorr structs. One schnorr struct by peers. These
	// structs are handling the process of distributively signing a message
	// We create one by giving it the info of the polynomials, the suite, and a
	// secretshare which is part of the long term distributed secret that we
	// just generated
	schnorrs := make([]*poly.Schnorr, threshold.N)
	for i, _ := range longterms {
		schnorrs[i] = poly.NewSchnorr(suite, threshold, longterms[i])
	}
	// For generating the random shared secrets, we can simply re-iterate the
	// previous process
	randoms := generateSharedSecrets()

	// To start signing something, we call NewRound on the schnorr structs, and
	// giving it the random secret freshly generated. NewRound is here to remind
	// that the security of the schnorr signing algorithm rest on the fact that
	// the random secret is REALLY random and fresh each time a new signature is
	// issued.
	// Again we must give the random secret share corresponding to the index of
	// the peer.
	for i, _ := range schnorrs {
		// The error here is related to the marshalling of the msg, if for any
		// reason it could not have happened
		if err := schnorrs[i].NewRound(randoms[i], msg); err != nil {
			panic(fmt.Errorf("NewRound failed for peer %d : %v", i, err))
		}

	}

	// In order to be able to sign something, a peer must first receive what is
	// called a partial signature of each others peers. Here we dsitribute the
	// partial signatures betwen everyone, but one could easily imagine where
	// simply one peer called the leader receives the partial signatures and no
	// one else. Then only it can sign anything.
	for i, _ := range schnorrs {
		// reveal the partial sig of this peer
		ps := schnorrs[i].RevealPartialSig()
		// and distribute it to every one else
		// Since the peer i is also a peer present in the schnorr setup it must
		// also give itself its own partial sig.
		for j, _ := range schnorrs {
			if err := schnorrs[j].AddPartialSig(ps); err != nil {
				panic(fmt.Errorf("AddPartialSig failed with sig of peer %d given to peer %d", i, j))
			}
		}
	}

	// Ouf ! At this point we can generate the signature !
	// Let's take the first peer for that. Again, each peers will generate the
	// exact final signatures.
	// The error returned as the second argument indicates if something went
	// wrong such as not enough partial signatures or wrong ones etc.
	sig0, err := schnorrs[0].Sig()
	if err != nil {
		panic(fmt.Errorf("Signature could not have been generated ... %v", err))
	}

	// Now the signature can be distributed exchanged or whatever.
	// You can at any time verify a given signature. For that simply gives the
	// signature to a schnorr struct constructed with the same longterm secret.
	// It does not matter if the schnorr struct has been used to issue others
	// signature in the meantime as long as it keeps the same longterm shared
	// secret.
	// You can see here that the schnorr struct is made to be a longterm struct,
	// that you can use many times, a bit like signature-as-a-service ;)

	// Let's take any other schnoorrs struct to verify it.
	if err := schnorrs[0].VerifySchnorrSig(sig0, msg); err != nil {
		panic(fmt.Errorf("Signature should have been verified : %v", err))
	}
	fmt.Println(sig0)
}
