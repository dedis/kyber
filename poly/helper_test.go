package poly

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

var testSuite = edwards.NewAES128SHA256Ed25519(true)

func generateKeyPair() *config.KeyPair {
	keypair := new(config.KeyPair)
	keypair.Gen(testSuite, random.Stream)
	return keypair
}

func generateKeyPairList(n int) []*config.KeyPair {
	l := make([]*config.KeyPair, n)
	for i := 0; i < n; i++ {
		l[i] = generateKeyPair()
	}
	return l
}

func generatePublicListFromPrivate(private []*config.KeyPair) []abstract.Point {
	l := make([]abstract.Point, len(private))
	for i := 0; i < len(private); i++ {
		l[i] = private[i].Public
	}
	return l
}

// Returns N dealers with M receivers with the right keys / public keys ...
func generateNDealerMReceiver(info Threshold, n, m int) ([]*Dealer, []*Receiver) {
	receiverKeys := generateKeyPairList(m)
	receiverPublics := generatePublicListFromPrivate(receiverKeys)
	receivers := make([]*Receiver, n)
	for i := 0; i < n; i++ {
		receivers[i] = NewReceiver(testSuite, info, receiverKeys[i])
	}
	dealers := make([]*Dealer, n)
	for i := 0; i < n; i++ {
		dealers[i] = NewDealer(testSuite, info, generateKeyPair(), generateKeyPair(), receiverPublics)
	}
	return dealers, receivers
}

// Same as produceNDealerMReceiver except that it make the exchange of Dealer / Response
func generateNMSetup(info Threshold, n, m int) ([]*Dealer, []*Receiver) {
	dealers, receivers := generateNDealerMReceiver(info, n, m)
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			resp, err := receivers[i].AddDealer(i, dealers[j])
			if err != nil {
				panic(fmt.Sprintf("Could not AddDealer %d on Receiver %d!", j, i))
			}
			dealers[j].AddResponse(i, resp)
		}
	}
	for j := 0; j < n; j++ {
		err := dealers[j].Certified()
		if err != nil {
			panic(fmt.Sprintf("Dealer's %d promise is not certified !", j))
		}
	}
	return dealers, receivers
}

// generateSharedSecret will return an array of SharedSecret structs
func generateSharedSecrets(info Threshold) []*SharedSecret {
	_, rs := generateNMSetup(info, info.N, info.N)
	secrets := make([]*SharedSecret, len(rs)) // len(rs) == n
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
func generateSchnorrStructs(info Threshold) []*Schnorr {
	longterms := generateSharedSecrets(info)
	schnorrs := make([]*Schnorr, info.N)
	for i, _ := range longterms {
		schnorrs[i] = NewSchnorr(testSuite, info, longterms[i])
	}
	return schnorrs
}
