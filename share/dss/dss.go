package dss

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/eddsa"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/dkg"
	"github.com/dedis/crypto/sign"
)

type DSS struct {
	suite        abstract.Suite
	secret       abstract.Scalar
	public       abstract.Point
	index        int
	participants []abstract.Point
	T            int
	long         *dkg.DistKeyShare
	random       *dkg.DistKeyShare
	longPoly     *share.PubPoly
	randomPoly   *share.PubPoly
	msg          []byte
	partials     []*share.PriShare
	partialsIdx  map[int]bool
	signed       bool
}

// XXX should we include a sessionID ? Can derive one from the two dist. key
// shares
type PartialSig struct {
	Partial   *share.PriShare
	Signature []byte
}

func NewDSS(suite abstract.Suite, secret abstract.Scalar, participants []abstract.Point,
	long, random *dkg.DistKeyShare, msg []byte, T int) (*DSS, error) {
	public := suite.Point().Mul(nil, secret)
	var i int
	var found bool
	for j, p := range participants {
		if p.Equal(public) {
			found = true
			i = j
			break
		}
	}
	if !found {
		return nil, errors.New("dss: public key not found in list of participants")
	}
	return &DSS{
		suite:        suite,
		secret:       secret,
		public:       public,
		index:        i,
		participants: participants,
		long:         long,
		longPoly:     share.NewPubPoly(suite, suite.Point().Base(), long.Commits),
		random:       random,
		randomPoly:   share.NewPubPoly(suite, suite.Point().Base(), random.Commits),
		msg:          msg,
		T:            T,
		partialsIdx:  make(map[int]bool),
	}, nil
}

// PartialSig generates the partial signature related to this DSS. This
// PartialSig can be broadcasted to every other participants or only to a
// trusted *combiner* as described in the paper.
// The signature format is compatible with EdDSA verification implementations
// XXX: almost, see https://github.com/dedis/crypto/issues/131
func (d *DSS) PartialSig() (*PartialSig, error) {
	// following the notations from the paper
	alpha := d.long.Share.V
	beta := d.random.Share.V
	hash := d.hashSig()
	right := d.suite.Scalar().Mul(hash, alpha)
	ps := &PartialSig{
		Partial: &share.PriShare{
			V: right.Add(right, beta),
			I: d.index,
		},
	}
	var err error
	ps.Signature, err = sign.Schnorr(d.suite, d.secret, ps.Hash(d.suite))
	if !d.signed {
		d.partialsIdx[d.index] = true
		d.partials = append(d.partials, ps.Partial)
		d.signed = true
	}
	return ps, err
}

func (d *DSS) ProcessPartialSig(ps *PartialSig) error {
	public, ok := findPub(d.participants, ps.Partial.I)
	if !ok {
		return errors.New("dss: partial signature with invalid index")
	}

	if err := sign.VerifySchnorr(d.suite, public, ps.Hash(d.suite), ps.Signature); err != nil {
		return err
	}

	if _, ok := d.partialsIdx[ps.Partial.I]; ok {
		return errors.New("dss: partial signature already received from peer")
	}

	hash := d.hashSig()
	idx := ps.Partial.I
	randShare := d.randomPoly.Eval(idx)
	longShare := d.longPoly.Eval(idx)
	right := d.suite.Point().Mul(longShare.V, hash)
	right.Add(randShare.V, right)
	left := d.suite.Point().Mul(nil, ps.Partial.V)
	if !left.Equal(right) {
		return errors.New("dss: partial signature not valid")
	}
	d.partialsIdx[ps.Partial.I] = true
	d.partials = append(d.partials, ps.Partial)
	return nil
}

func (d *DSS) EnoughPartialSig() bool {
	return len(d.partials) >= d.T
}

func (d *DSS) Signature() ([]byte, error) {
	if !d.EnoughPartialSig() {
		return nil, errors.New("dkg: not enough partial signatures to sign.")
	}
	gamma, err := share.RecoverSecret(d.suite, d.partials, d.T, len(d.participants))
	if err != nil {
		fmt.Println("or here")
		return nil, err
	}
	// RandomPublic || gamma
	var buff bytes.Buffer
	d.random.Public().MarshalTo(&buff)
	gamma.MarshalTo(&buff)
	return buff.Bytes(), nil
}

func (d *DSS) hashSig() abstract.Scalar {
	// H(R || A || msg) with
	//  * R = distributed random "key"
	//  * A = distributed public key
	//  * msg = msg to sign
	h := sha512.New()
	d.random.Public().MarshalTo(h)
	d.long.Public().MarshalTo(h)
	h.Write(d.msg)
	return d.suite.Scalar().SetBytes(h.Sum(nil))
}

func Verify(suite abstract.Suite, public abstract.Point, msg, sig []byte) error {
	return eddsa.Verify(public, msg, sig)
}

func (ps *PartialSig) Hash(s abstract.Suite) []byte {
	return ps.Partial.Hash(s)
}

// XXX: maybe put that as internal package for vss & dkg since they both use the
// same function
func findPub(list []abstract.Point, i int) (abstract.Point, bool) {
	if i >= len(list) {
		return nil, false
	}
	return list[i], true
}
