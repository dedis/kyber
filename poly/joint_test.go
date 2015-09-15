package poly

import (
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
	"testing"
)

var edward = edwards.NewAES128SHA256Ed25519(false)

func generateKeyPair() *config.KeyPair {
	keypair := new(config.KeyPair)
	keypair.Gen(edward, random.Stream)
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

// produce M receivers from their private/pub keys
func generateReceivers(info PolyInfo, keys []*config.KeyPair) []*Receiver {
	n := len(keys)
	l := make([]*Receiver, n)
	for i := 0; i < n; i++ {
		l[i] = NewReceiver(info, keys[i])
	}
	return l
}

// Produce N dealers with the public keys of the M receivers
func generateDealers(n int, info PolyInfo, receiverList []abstract.Point) []*Dealer {
	d := make([]*Dealer, n)
	for i := 0; i < n; i++ {
		d[i] = NewDealer(info, generateKeyPair(), generateKeyPair(), receiverList)
	}
	return d
}

// Returns N dealers with M receivers with the right keys / public keys ...
func generateNDealerMReceiver(info PolyInfo, n, m int) ([]*Dealer, []*Receiver) {
	receiverKeys := generateKeyPairList(m)
	receiverPublics := generatePublicListFromPrivate(receiverKeys)
	receivers := generateReceivers(info, receiverKeys)
	dealers := generateDealers(n, info, receiverPublics)
	return dealers, receivers
}

// Same as produceNDealerMReceiver except that it make the exchange of Dealer / Response
func generateNMSetup(info PolyInfo, n, m int) ([]*Dealer, []*Receiver) {
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

/////// TESTING ///////

func TestReceiverAddDealer(t *testing.T) {
	dealers, receivers := generateNDealerMReceiver(PolyInfo{edward, 2, 3, 3}, 3, 3)
	// Test adding one dealer
	_, e1 := receivers[0].AddDealer(0, dealers[0])
	if e1 != nil {
		t.Error(fmt.Sprintf("AddDealer should not return an error : %v", e1))
	}

	// Test adding another dealer with same index
	_, e2 := receivers[0].AddDealer(0, dealers[1])
	if e2 != nil {
		t.Error(fmt.Sprintf("AddDealer should not return an error : %v", e2))
	}

	// Test adding another dealer with different index !
	_, e3 := receivers[0].AddDealer(1, dealers[2])
	if e3 == nil {
		t.Error(fmt.Sprintf("AddDealer should have returned an error (adding dealer to a different index for same receiver)"))
	}
}

// Test the AddReponse func
func TestRightDealerAddResponse(t *testing.T) {
	// Test if all goes well with the right inputs
	n := 3
	m := 3
	dealers, receivers := generateNDealerMReceiver(PolyInfo{edward, 2, 3, 3}, n, m)
	// for each receiver
	for i := 0; i < m; i++ {
		// add all the dealers
		for j := 0; j < n; j++ {
			resp, err := receivers[i].AddDealer(i, dealers[j])
			if err != nil {
				t.Error("AddDealer should not generate error")
			}
			// then give the response back to the dealer
			err = dealers[j].AddResponse(i, resp)
			if err != nil {
				t.Error(fmt.Sprintf("AddResponse should not generate any error : %v", err))
			}
		}
	}
	for j := 0; j < n; j++ {
		val := dealers[j].Certified()
		if val != nil {
			t.Error(fmt.Sprintf("Dealer %d should be certified : ", j, val))
		}
	}

}

// Test the AddReponse func with wrong inputs
func TestWrongDealerAddResponse(t *testing.T) {
	n := 2
	m := 3
	dealers, receivers := generateNDealerMReceiver(PolyInfo{edward, 2, 3, 3}, n, m)
	r1, _ := receivers[0].AddDealer(0, dealers[0])
	err := dealers[0].AddResponse(1, r1)
	if err == nil {
		t.Error("AddResponse should have returned an error when given the wrong index share")
	}
	// We may do others tests but I leave it for now as a discussion because, all theses tests are based on the promise package which is already well tested
}

func TestProduceSharedSecret(t *testing.T) {
	n := 3
	m := 3
	_, receivers := generateNMSetup(PolyInfo{edward, 2, 3, 3}, n, m)
	s1, err := receivers[0].ProduceSharedSecret()
	if err != nil {
		t.Error(fmt.Sprintf("ProduceSharedSecret should not gen any error : %v", err))
	}
	s2, err := receivers[1].ProduceSharedSecret()
	if err != nil {
		t.Error(fmt.Sprintf("ProdueSharedSecret should not gen any error : %v", err))
	}

	if !s1.Pub.Equal(s2.Pub) {
		t.Error("SharedSecret's polynomials should be equals")
	}

	if v := s1.Pub.Check(receivers[1].index, *s2.Share); v == false {
		t.Error("SharedSecret's share can not be verified using another's receiver pubpoly")
	}
	if v := s2.Pub.Check(receivers[0].index, *s1.Share); v == false {
		t.Error("SharedSecret's share can not be verified using another's receiver pubpoly")
	}
}
