// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
package daga

// TODO decide / review method vs functions + "granularity of parameters"
// I'd say put DAGA "primitives" as functions and create methods on clients and servers that use those,
// put the daga primitives into kyber and the rest into a DAGA package somewhere else in cothority
// TODO QUESTION FIXME how to securely erase secrets ?
// TODO see what to export and what not, for now mostly everything private
import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/kyber/util/key"
	"hash"
	"io"
)

// Suite represents the set of functionalities needed for the DAGA package to operate
// the purpose of the Suite is to allow multiple implementations,
// (e.g one using EC crypto on edwards25519 curve and another one using a Schnorr group like in the original DAGA paper,
// originally "DAGA assumes a cyclic multiplicative group G of prime order q, where p=2q+1,
// where the Discrete Logarithm and Decisional Diffie-Hellman assumptions hold"
// quoted from Syta - Identity Management Through Privacy Preserving Aut)
//
// concrete suites are defined in daga/suite.go
type Suite interface {
	kyber.Group
	kyber.Random
	key.Generator     // needed since sometimes/in some groups we need to take care while generating secrets, (e.g in edwards25519, to avoid small subgroup attacks, need to mask some bits)
	kyber.HashFactory // FIXME remove this hashfactory and defines hash1 hash2 as hash functions that should behaves like RO and that returns scalars and points respectively
	// FIXME review where Hash2 should be called instead of Hash and how, I might have used Hash everywhere, bad
	hashTwo() hash.Hash // DAGA needs another hash function (that can be of another size depending on the concrete groups used)
}

// AuthenticationContext holds all the constants of a particular DAGA authentication round.
//
// In DAGA "we define an authentication round with respect to a particular authentication
// context C. Each authentication request, regardless of the identity of the originating
// client, belongs to the same round if it is made with respect to C. All requests within
// the same round are linkable, that is, each time a client i authenticates, the servers
// will be able to link these requests as coming from some client from" the group.
//
// The DAGA authentication context is established and published 'collectively' by the servers before an authentication round.
// An authentication context might be one time, where each client is expected to make exactly one authentication request
// or a context may remain valid for certain period of time or some maximum number of
// authentications made by a single clients or all of clients in g.x. Since the servers can
// keep track of each anonymous client’s authentication request, a client may be allowed
// to make up to k requests so that each request beyond that is rejected regardless of the
// validity of the supplied authentication message. After a context expires, all servers
// securely erase their per-round secrets r making it impossible to process authentication
// messages within this context.
// See Syta - Identity Management Through Privacy Preserving Aut Chapter 4.7.3

// g contains the 'group' (<- poor choice of word) definition, that is the public keys of the clients (g.x) and the servers (g.y)
//
// r contains the commitments of the servers to their unique per-round secrets
//
// h contains the unique per-round generators of the group (<- the algebraic structure) associated to each clients
// TODO maybe remove the g thing (but we lose reading "compatibility with daga paper") and have a slices of struct {x, h} and struct {y, r} instead to enforce same length
type AuthenticationContext struct {
	g struct {
		x []kyber.Point
		y []kyber.Point
	}
	r []kyber.Point
	h []kyber.Point
}

// returns a pointer to a newly allocated authenticationContext initialized with :
//
// x the public keys of the clients
//
// y the public keys of the servers
//
// r the commitments of the servers to their unique per-round secrets
//
// h the unique per-round generators of the group associated to each clients
func NewAuthenticationContext(x, y, r, h []kyber.Point) (*AuthenticationContext, error) {
	if len(x) != len(h) || len(y) != len(r) || len(x) == 0 || len(y) == 0 {
		return nil, errors.New("NewAuthenticationContext: illegal length, len(x) != len(h) Or len(y) != len(r) Or zero length slices")
	}
	return &AuthenticationContext{
		g: struct {
			x []kyber.Point
			y []kyber.Point
		}{
			x: x,
			y: y,
		},
		r: r,
		h: h,
	}, nil
}

// returns the public keys of the members of an authenticationContext, client keys in X and server keys in Y
func (ac AuthenticationContext) Members() (X, Y []kyber.Point) {
	return ac.g.x, ac.g.y
}

// returns the per-round generator of the clients for this authenticationContext
func (ac AuthenticationContext) ClientsGenerators() []kyber.Point {
	return ac.h
}

// Signs using schnorr signature scheme over the group of the Suite
// QUESTION to me this is a bad idea ?! better to have Sign be a required function listed in the Suite,
// QUESTION where concrete suite implementation make sure that the signature scheme works well with the chosen group etc..
func SchnorrSign(suite Suite, private kyber.Scalar, msg []byte) (s []byte, err error) {
	//Input checks
	if private == nil {
		return nil, errors.New("cannot sign, no private key provided")
	}
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}

	s, err = schnorr.Sign(suite, private, msg)
	if err != nil {
		return nil, errors.New("failed to sign the message: " + err.Error())
	}
	return s, nil
}

// SchnorrVerify checks if a Schnorr signature generated using SchnorrSign is valid and returns an error if it is not the case
// QUESTION same as above
func SchnorrVerify(suite Suite, public kyber.Point, msg, sig []byte) (err error) {
	//Input checks
	if public == nil {
		return fmt.Errorf("cannot verify, no public key provided")
	}
	if len(msg) == 0 {
		return fmt.Errorf("empty message")
	}
	if len(sig) == 0 {
		return fmt.Errorf("empty signature")
	}

	err = schnorr.Verify(suite, public, msg, sig)
	return err
}

/*ToBytes is a utility function to convert an AuthenticationContext into []byte, used in signatures*/
// QUESTION WTF no other way ?
func (ac AuthenticationContext) ToBytes() (data []byte, err error) {
	temp, e := PointArrayToBytes(ac.g.x)
	if e != nil {
		return nil, fmt.Errorf("Error in X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(ac.g.y)
	if e != nil {
		return nil, fmt.Errorf("Error in Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(ac.h)
	if e != nil {
		return nil, fmt.Errorf("Error in H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(ac.r)
	if e != nil {
		return nil, fmt.Errorf("Error in R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*PointArrayToBytes is a utility function to convert a kyber.Point array into []byte, used in signatures*/
// QUESTION same as above + if this is the way to go make it a method of []kyber.Point for consistency and rename it marshalbinary
func PointArrayToBytes(array []kyber.Point) (data []byte, err error) {
	for _, p := range array {
		temp, e := p.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}

/*ScalarArrayToBytes is a utility function to convert a kyber.Scalar array into []byte, used in signatures*/
// QUESTION same as above
func ScalarArrayToBytes(array []kyber.Scalar) (data []byte, err error) {
	for _, s := range array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}

// TODO WTF, no other way ? + rename marshalbinary for consistency
/*ToBytes is a helper function used to convert a ClientMessage into []byte to be used in signatures*/
func (msg AuthenticationMessage) ToBytes() (data []byte, err error) {
	data, e := msg.c.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in context: %s", e)
	}

	temp, e := PointArrayToBytes(msg.sCommits)
	if e != nil {
		return nil, fmt.Errorf("error in S: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.t0.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in T0: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.p0.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in proof: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

//generateClientGenerator generates a per-round generator for a given client
func GenerateClientGenerator(suite Suite, index int, commits []kyber.Point) (gen kyber.Point, err error) {
	if index < 0 {
		return nil, fmt.Errorf("Wrond index: %d", index)
	}
	if len(commits) <= 0 {
		return nil, fmt.Errorf("Wrong commits:\n%v", commits)
	}
	// QUESTION FIXME why sha3(sha512()) was previously used ?
	// TODO remember that I didn't write it, see later when building service if correct etc..
	// QUESTION should we ensure that no 2 client get same generator ?
	hasher := sha512.New()
	var writer io.Writer = hasher // ...
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, uint32(index)) // TODO verify
	writer.Write(idb)
	for _, R := range commits {
		R.MarshalTo(writer)
	}
	hash := hasher.Sum(nil)
	hasher = suite.Hash()
	hasher.Write(hash)
	gen = suite.Point().Mul(suite.Scalar().SetBytes(hasher.Sum(nil)), nil)
	return
}
