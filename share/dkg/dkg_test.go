package vss

import (
	"crypto/rand"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share/vss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var suite = ed25519.NewAES128SHA256Ed25519(false)

var nbParticipants = 7

var partPubs []abstract.Point
var partSec []abstract.Scalar

var dkgs []*DistKeyGenerator

func dkgGen() []*DistKeyGenerator {
	dkgs := make([]*DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := NewDistKeyGenerator(suite, partSec[i], partPubs, random.Stream, nbParticipants/2+1)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func genPair() (abstract.Scalar, abstract.Point) {
	sc := suite.Scalar().Pick(random.Stream)
	return sc, suite.Point().Mul(nil, sc)
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	rand.Read(buff[:])
	return buff
}

func init() {
	partPubs = make([]abstract.Point, nbParticipants)
	partSec = make([]abstract.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen()
}

func TestDKGNewDistKeyGenerator(t *testing.T) {
	long := partSec[0]
	dkg, err := NewDistKeyGenerator(suite, long, partPubs, random.Stream, nbParticipants/2+1)
	assert.Nil(t, err)
	assert.NotNil(t, dkg.dealer)

	sec, _ := genPair()
	_, err = NewDistKeyGenerator(suite, sec, partPubs, random.Stream, nbParticipants/2+1)
	assert.Error(t, err)

}

func TestDKGDeal(t *testing.T) {
	dkg := dkgs[0]

	deals := dkg.Deals()
	assert.Len(t, deals, nbParticipants-1)

	for i := range deals {
		assert.NotNil(t, deals[i])
		assert.Equal(t, uint32(0), deals[i].Index)
	}

	v, ok := dkg.verifiers[dkg.index]
	assert.True(t, ok)
	assert.NotNil(t, v)
}

func TestDKGProcessDeal(t *testing.T) {
	dkgs = dkgGen()
	dkg := dkgs[0]
	deals := dkg.Deals()

	rec := dkgs[1]
	deal := deals[1]
	assert.Equal(t, int(deal.Index), 0)
	assert.Equal(t, uint32(1), rec.index)

	// good deal
	resp, err := rec.ProcessDeal(deal)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusApproval, resp.Response.Status)
	assert.Nil(t, err)
	_, ok := rec.verifiers[deal.Index]
	require.True(t, ok)
	assert.Equal(t, uint32(0), resp.Index)

	// duplicate
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)

	// wrong index
	goodIdx := deal.Index
	deal.Index = uint32(nbParticipants + 1)
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	deal.Index = goodIdx

	// wrong deal
	wrongSig := randomBytes(len(deal.Deal.Signature))
	goodSig := deal.Deal.Signature
	deal.Deal.Signature = wrongSig
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	deal.Deal.SessionID = goodSig
}

func TestDKGProcessResponse(t *testing.T) {
	dkgs = dkgGen()
	dkg := dkgs[0]
	deals := dkg.Deals()
	v, ok := dkg.verifiers[0]
	require.NotNil(t, v)
	require.True(t, ok)

	rec := dkgs[1]
	deal := deals[1]
	sig := deal.Deal.Signature
	deal.Deal.Signature = randomBytes(len(sig))

	// give a wrong deal
	resp, err := rec.ProcessDeal(deal)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.Response.Status)
	assert.Nil(t, err)
	deal.Deal.Signature = sig

	// no verifier tied to Response
	v = dkg.verifiers[0]
	require.NotNil(t, v)
	delete(dkg.verifiers, 0)
	j, err := dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.NotNil(t, err)
	dkg.verifiers[resp.Index] = v

	// invalid response
	goodSig := resp.Response.Signature
	resp.Response.Signature = randomBytes(len(goodSig))
	j, err = dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.Error(t, err)
	resp.Response.Signature = goodSig

	// valid complaint from our deal
	j, err = dkg.ProcessResponse(resp)
	assert.NotNil(t, j)
	assert.Nil(t, err)

	// valid complaint from another deal from another peer
	dkg2 := dkgs[2]
	deals2 := dkg2.Deals()
	// fake a wrong deal
	deal21 := deals2[1]
	deal20 := deals2[0]
	sig21 := deal21.Deal.Signature
	deal21.Deal.Signature = randomBytes(32)

	resp, err = rec.ProcessDeal(deal21)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.Response.Status)
	deal21.Deal.Signature = sig21

	// give it to the first peer
	// XXX Should we let peers know about approval/complaint for non-received
	// deal yet ?
	// process dealer 2's deal
	dkg.ProcessDeal(deal20)
	// process response from peer 1
	j, err = dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.Nil(t, err)

	// Justification part:
	// give the complaint to the dealer
	j, err = dkg2.ProcessResponse(resp)
	assert.Nil(t, err)
	assert.NotNil(t, j)

	// hack because all is local, and resp has been modified locally by dkg2's
	// verifier
	resp.Response.Status = vss.StatusComplaint
	err = dkg.ProcessJustification(j)
	assert.Nil(t, err)

	// remove verifiers
	v = dkg.verifiers[j.Index]
	delete(dkg.verifiers, j.Index)
	err = dkg.ProcessJustification(j)
	assert.Error(t, err)
	dkg.verifiers[j.Index] = v
}

/*func TestReceiverAddDeal(t *testing.T) {*/
//dealers, receivers := generateNDealerMReceiver(Threshold{3, 3, 4}, 3, 4)
//// Test adding one dealer
//_, e1 := receivers[0].AddDeal(0, dealers[0])
//if e1 != nil {
//t.Error(fmt.Sprintf("AddDeal should not return an error : %v", e1))
//}

//// Test adding another dealer with same index
//_, e2 := receivers[0].AddDeal(0, dealers[1])
//if e2 != nil {
//t.Error(fmt.Sprintf("AddDeal should not return an error : %v", e2))
//}

//// Test adding another dealer with different index !
//_, e3 := receivers[0].AddDeal(1, dealers[2])
//if e3 == nil {
//t.Error(fmt.Sprintf("AddDeal should have returned an error (adding dealer to a different index for same receiver)"))
//}
//}

//// Test the AddReponse func
//func rightDealerAddResponse(t *testing.T) {
//// Test if all goes well with the right inputs
//n := 3
//m := 4
//dealers, receivers := generateNDealerMReceiver(Threshold{3, 3, 4}, n, m)
//states := make([]*State, len(dealers))
//for i := 0; i < len(dealers); i++ {
//states[i] = new(State).Init(*dealers[i])
//}
//// for each receiver
//for i := 0; i < m; i++ {
//// add all the dealers
//for j := 0; j < n; j++ {
//resp, err := receivers[i].AddDeal(i, dealers[j])
//if err != nil {
//t.Error("AddDeal should not generate error")
//}
//// then give the response back to the dealer
//err = states[j].AddResponse(i, resp)
//if err != nil {
//t.Error(fmt.Sprintf("AddResponse should not generate any error : %v", err))
//}
//}
//}
//for j := 0; j < n; j++ {
//val := states[j].DealCertified()
//if val != nil {
//t.Error(fmt.Sprintf("Dealer %d should be certified : %v", j, val))
//}
//}

//}
//func TestDealerAddResponse(t *testing.T) {
//rightDealerAddResponse(t)
//wrongDealerAddResponse(t)
//}

//// Test the AddReponse func with wrong inputs
//func wrongDealerAddResponse(t *testing.T) {
//n := 3
//m := 4
//dealers, receivers := generateNDealerMReceiver(Threshold{3, 3, 4}, n, m)
//r1, _ := receivers[0].AddDeal(0, dealers[0])
//state := new(State).Init(*dealers[0])
//err := state.AddResponse(1, r1)
//if err == nil {
//t.Error("AddResponse should have returned an error when given the wrong index share")
//}
//}

//func TestProduceSharedSecret(t *testing.T) {
//T := 4
//m := 5
//_, receivers := generateNMSetup(Threshold{T, m, m}, T, m)
//s1, err := receivers[0].ProduceSharedSecret()
//if err != nil {
//t.Error(fmt.Sprintf("ProduceSharedSecret should not gen any error : %v", err))
//}
//s2, err := receivers[1].ProduceSharedSecret()
//if err != nil {
//t.Error(fmt.Sprintf("ProdueSharedSecret should not gen any error : %v", err))
//}

//if !s1.Pub.Equal(s2.Pub) {
//t.Error("SharedSecret's polynomials should be equals")
//}

//if v := s1.Pub.Check(receivers[1].index, *s2.Share); v == false {
//t.Error("SharedSecret's share can not be verified using another's receiver pubpoly")
//}
//if v := s2.Pub.Check(receivers[0].index, *s1.Share); v == false {
//t.Error("SharedSecret's share can not be verified using another's receiver pubpoly")
//}
//}

//func TestPolyInfoMarshalling(t *testing.T) {
//pl := Threshold{
//T: 3,
//R: 5,
//N: 8,
//}
//b := new(bytes.Buffer)
//err := testSuite.Write(b, &pl)
//if err != nil {
//t.Error(fmt.Sprintf("PolyInfo MarshalBinary should not return error : %v", err))
//}
//pl2 := Threshold{}
//err = testSuite.Read(bytes.NewBuffer(b.Bytes()), &pl2)
//if err != nil {
//t.Error(fmt.Sprintf("PolyInfo UnmarshalBinary should not return error : %v", err))
//}

//if !pl.Equal(pl2) {
//t.Error(fmt.Sprintf("PolyInfo's should be equals: \npl1 : %+v\npl2 : %+v", pl, pl2))
//}

//}

//func TestProduceSharedSecretMarshalledDealer(t *testing.T) {
//// Test if all goes well with the right inputs
//n := 3
//m := 3
//pl := Threshold{2, 3, 3}
//dealers, receivers := generateNDealerMReceiver(pl, n, m)
//// for each receiver
//for i := 0; i < m; i++ {
//// add all the dealers
//for j := 0; j < n; j++ {
//b := new(bytes.Buffer)
//err := testSuite.Write(b, dealers[j])
//if err != nil {
//t.Error("Write(Dealer) should not gen any error : ", err)
//}
//buf := b.Bytes()
//bb := bytes.NewBuffer(buf)
//d2 := new(Deal).UnmarshalInit(pl.T, pl.R, pl.N, testSuite)
//err = testSuite.Read(bb, d2)
//if err != nil {
//t.Error("Read(Dealer) should not gen any error : ", err)
//}
//receivers[i].AddDeal(i, d2)
//}
//}
//_, err := receivers[0].ProduceSharedSecret()
//if err != nil {
//t.Error(fmt.Sprintf("ProduceSharedSecret with Marshalled dealer should work : %v", err))
//}
/*}*/
