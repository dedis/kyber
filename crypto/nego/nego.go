// Package nego implements cryptographic negotiation
// and secret entrypoint finding.
package nego

import (
	"fmt"
	"errors"
	"crypto/cipher"
	"encoding/binary"
	"dissent/crypto"
)


type Entry struct {
	Suite crypto.Suite	// Ciphersuite this public key is drawn from
	PubKey crypto.Point	// Public key of this entrypoint's owner
	Data []byte		// Entrypoint data decryptable by owner
}


// Writer produces a cryptographic negotiation header,
// which conceals a variable number of "entrypoints"
// within a variable-length binary blob of random-looking bits.
// Each entrypoint hidden in the blob is discoverable and usable only
// by the owner of a particular public key.
// Different public keys may be drawn from different ciphersuites,
// in any combination, without coordination between the ciphersuites.
//
// Each entrypoint contains a short fixed-length blob of encrypted data,
// which the owner of the entrypoint can decrypt and use
// to obtain keys and pointers to the "real" content.
// This "real" content is typically located after the negotiation header
// and encrypted with a symmetric key included in the entrypoint data,
// which can be (but doesn't have to be) shared by many or all entrypoints.
//
type Writer struct {
	layout
}


// A ciphersuite used in a negotiation header.
type suiteKey struct {

	// Ephemeral Diffie-Hellman key for all key-holders using this suite.
	// Should have a uniform representation, e.g., an Elligator point.
	dhpri crypto.Secret
	dhpub crypto.Point
	dhrep []byte
}

/*
func (s *suiteKey) fresh(suite crypto.Suite) {
	dhpri := entry.suite.Secret().Pick(rand)
	dhpub := entry.Suite.Point().Mul(nil, dhpri)
	dhrep := dhpub.UniformEncode()
	suites[suite] = suite{dhpri,dhpub}
}
*/


// Determine all the alternative DH point positions for a ciphersuite.
func suitePos(suite crypto.Suite, levels int) []int {
	altpos := make([]int, levels)
	ptlen := suite.PointLen()		// XXX UniformLen()

	// Alternative 0 is always at position 0, so start with level 1.
	levofs := ptlen		// starting offset for current level
	//fmt.Printf("Suite %s positions:\n", suite.String())
	for i := 1; i < levels; i++ {
		str := fmt.Sprintf("NegoCipherSuite:%s:%d",
					suite.String(), i)

		h := suite.Hash()
		h.Write([]byte(str))
		b := h.Sum(nil)

		levlen := 1 << uint(i)	// # alternative positions at this level
		levmask := levlen - 1	// alternative index mask
		levidx := int(binary.BigEndian.Uint32(b)) & levmask
		altpos[i] = levofs + levidx * ptlen

		//fmt.Printf("%d: idx %d/%d pos %d\n",
		//		i, levidx, levlen, altpos[i])

		levofs += levlen * ptlen	// next level table offset
	}
	return altpos
}


// Try to place a ciphersuite starting at level i,
// and scanning in direction inc in case of conflict.
// Returns true if suite successfully placed, false if not.
func (w *Writer) dhInsert(suite crypto.Suite, altpos []int, i,inc int) bool {
	nlevels := len(altpos)
	if i >= nlevels {			// clamp starting point
		i = nlevels-1
	}
	ptlen := suite.PointLen()		// XXX UniformLen()
	var n node
	for ; i >= 0 && i < nlevels; i += inc {
		lo := altpos[i]			// compute byte extent
		hi := lo + ptlen
		n.init(suite, i, lo, hi)	// create suitable node
		//fmt.Printf("try insert %s at %d-%d\n", suite.String(), lo, hi)
		if w.layout.insert(&n) {
			//fmt.Printf("  success\n")
			return true		// success
		}
	}
	return false	// no available position found in that direction
}


// Scan a tentative Diffie-Hellman point layout for conflicts,
// in which an XOR-encoded point would be scrambled by
// the encoding of another point higher in the layout,
// assuming points are encoded in order of increasing position.
/*
func (w *Writer) conflicts() []*node {
	conf := make([]*node, 0)
	layout.traverse(func(n *node){
		suite := n.obj.(crypto.Suite)
		...
	})
	return conf
}
*/


// Initialize a Writer to produce one or more negotiation header
// containing a specified set of entrypoints,
// whose owners' public keys are drawn from a given set of ciphersuites.
//
// The caller must provide a map 'suiteLevel' with one key per ciphersuite,
// whose value is the maximum "level" in the header 
// at which the ciphersuite's ephemeral Diffie-Hellman Point may be encoded.
// This maximum level must be standardized for each ciphersuite,
// and should be log2(maxsuites), where maxsuites is the maximum number
// of unique ciphersuites that are likely to exist when this suite is defined.
//
// All entrypoints will carry a payload entryLen bytes long,
// although the content of these payloads need not be specified yet.
// This function lays out the entrypoints in the negotiation header,
// and returns the total size of the negotiation headers
// that will be produced from this layout.
//
// After this initialization and layout computation,
// multiple independent negotiation headers with varying entrypoint data
// may be produced more efficiently via Write().
//
func (w *Writer) Init(suiteLevel map[crypto.Suite]int,
			entryLen int, entrypoints []Entry,
			rand cipher.Stream) (int,error) {

	w.layout.init()

	// We use a big.Int as a bit-vector to allocate header space.
	//alloc := big.NewInt(0)

	// Determine the set of ciphersuites in use.
/*
	suites := make(map[crypto.Suite]struct{})
	for i := range(entrypoints) {
		entry := entrypoints[i]
		if _,ok := suites[suite]; !ok {
			// First time we've seen this ciphersuite.
			suites[suite] = struct{}{}
		}
	}
*/

	// Compute the alternative DH point positions for each ciphersuite.
	sPos := make(map[crypto.Suite][]int)
	for suite,levels := range suiteLevel {
		sPos[suite] = suitePos(suite,levels)
	}

	// Start all suites' points at some default level
	// estimated based on the log2 of the total number of ciphersuites.
	level := 0
	for l := len(suiteLevel); l != 0; l >>= 1 {
		level++
	} 
	fmt.Printf("%d suites, default level %d\n", len(suiteLevel), level)

	// Initially lay out the ciphersuites' Diffie-Hellman points,
	// preferring this default initial level to start with,
	// shifting to lower levels first on hash conflicts,
	// or to higher levels only as a last resort.
	for suite,_ := range suiteLevel {
		altpos := sPos[suite]
		if !w.dhInsert(suite, altpos, level, -1) {
			if !w.dhInsert(suite, altpos, level, +1) {
				return 0,errors.New(
					"Unable to layout ciphersuite " +
					suite.String())
			}
		}
	}

	fmt.Println("initial ciphersuite layout:")
	w.layout.dump();

	// Greedily shift ciphersuites to lower alternatives when possible,
	// starting with the ciphersuite currently at the highest position.
	var headerSize int
	for {
		top := w.layout.top()
		suite := top.obj.(crypto.Suite)
		//fmt.Printf("try moving %s at %d-%d down from level %d\n",
		//		suite.String(), top.lo, top.hi, top.level)
		if !w.dhInsert(suite, sPos[suite], top.level-1, -1) {
			headerSize = top.hi
			break			// no more compaction possible
		}

		//fmt.Printf("success, layout after insertion:\n")
		//w.layout.dump()

		w.layout.remove(top)

		//fmt.Printf("success, new layout:\n")
		//w.layout.dump()
	}

	fmt.Println("final ciphersuite layout:")
	w.layout.dump();

	return headerSize,nil
}


// 
//func (w *Writer) Write(entryData map[Entry][]byte, suffix []byte)

