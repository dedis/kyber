package dcnet

import (
	"bytes"
	//"encoding/hex"
	"crypto/cipher"
	"dissent/crypto"
)

type ownedCoder struct {
	suite crypto.Suite

	// Length of Key and MAC part of verifiable DC-net point
	keylen, maclen int

	// Verifiable DC-nets secrets shared with each peer.
	vkeys []crypto.Secret

	// The sum of all our verifiable DC-nets secrets.
	vkey crypto.Secret

	// Pseudorandom DC-nets streams shared with each peer.
	// On clients, there is one DC-nets stream per trustee.
	// On trustees, there ois one DC-nets stream per client.
	dcstreams []cipher.Stream

	// Decoding state, used only by the relay
	point crypto.Point
	pnull crypto.Point	// neutral/identity element
	xorbuf []byte
}

// OwnedCoderFactory creates a DC-net cell coder for "owned" cells:
// cells having a single owner identified by a public pseudonym key.
//
// This CellCoder upports variable-length payloads.
// For small payloads that can be embedded into half a Point,
// the encoding consists of a single verifiable DC-net point.
// For larger payloads, we use one verifiable DC-net point
// to transmit a key and a MAC for the associated variable-length,
// symmetric-key crypto based part of the cell.
func OwnedCoderFactory() CellCoder {
	return new(ownedCoder)
}


// For now just hard-code a single choice of trap-encoding word size
// for maximum simplicity and efficiency.
// We'll evaluate later whether we need to make it dynamic.
const wordbits = 32
type word uint32


///// Common methods /////

// Compute the size of the symmetric AES-encoded part of an encoded ciphertext.
func (c *ownedCoder) symmCellSize(payloadlen int) int {

	// If data fits in the space reserved for the key
	// in the verifiable DC-net point,
	// we can just inline the data in the point instead of the key.
	// (We'll still use the MAC part of the point for validation.)
	if payloadlen <= c.keylen {
		return 0
	}

	// Otherwise the point is used to hold an encryption key and a MAC,
	// and the payload is symmetric-key encrypted.
	// XXX trap encoding
	return payloadlen

/*
	// Compute number of payload words we will need for trap-encoding.
	words := (payloadlen*8 + wordbits-1) / wordbits

	// Number of bytes worth of trap-encoded payload words,
	// after padding the payload up to the next word boundary.
	wordbytes := (words*wordbits+7)/8

	// We'll need to follow the payload with an inversion bitmask,
	// one bit per trap-encoded word.
	invbytes := (words+7)/8

	// Total cell is the verifiable DC-nets point, plus payload,
	// plus inversion bitmask.  (XXX plus ZKP/signature.)
	return c.suite.PointLen() + wordbytes + invbytes
*/
}

func (c *ownedCoder) commonSetup(suite crypto.Suite) {
	c.suite = suite

	// Divide the embeddable data in the verifiable point
	// between an encryption key and a MAC check
	c.keylen = suite.KeyLen()
	c.maclen = suite.Point().PickLen() - c.keylen
	if c.maclen < c.keylen*3/4 {
		panic("misconfigured ciphersuite: MAC too small!")
	}
}


///// Client methods /////

func (c *ownedCoder) ClientCellSize(payloadlen int) int {

	// Clients must produce a point plus the symmetric ciphertext
	return c.suite.PointLen() + c.symmCellSize(payloadlen)
}

func (c *ownedCoder) ClientSetup(suite crypto.Suite,
				peerstreams []cipher.Stream) {
	c.commonSetup(suite)

	// Use the provided master streams to seed
	// a pseudorandom public-key encryption secret, and
	// a pseudorandom DC-nets substream shared with each peer.
	npeers := len(peerstreams)
	c.vkeys = make([]crypto.Secret, npeers)
	c.vkey = suite.Secret()
	c.dcstreams = make([]cipher.Stream, npeers)
	for j := range(peerstreams) {
		c.vkeys[j] = suite.Secret().Pick(peerstreams[j])
		c.vkey.Add(c.vkey, c.vkeys[j])
		c.dcstreams[j] = crypto.SubStream(suite, peerstreams[j])
	}
}

func (c *ownedCoder) ClientEncode(payload []byte, payloadlen int,
				histoream cipher.Stream) []byte {

	// Compute the verifiable blinding point for this cell.
	// To protect clients from equivocation by relays,
	// we choose the blinding generator for each cell pseudorandomly
	// based on the history of all past downstream messages
	// the client has received from the relay.
	// If any two honest clients disagree on this history,
	// they will produce encryptions based on unrelated generators,
	// rendering the cell unintelligible,
	// so that any data the client might be sending based on
	// having seen a divergent history gets suppressed.
	p := c.suite.Point()
	p.Pick(nil, histoream)
	p.Encrypt(p, c.vkey)

	// Encode the payload data, if any.
	payout := make([]byte, c.symmCellSize(payloadlen))
	if payload != nil {
		// We're the owner of this cell.
		if len(payload) <= c.keylen {
			c.inlineEncode(payload, p)
		} else {
			c.ownerEncode(payload, payout, p)
		}
	}

	// XOR the symmetric DC-net streams into the payload part
	for i := range(c.dcstreams) {
		c.dcstreams[i].XORKeyStream(payout, payout)
	}

	// Build the full cell ciphertext
	out := p.Encode()
	out = append(out, payout...)
	return out
}

func (c *ownedCoder) inlineEncode(payload []byte, p crypto.Point) {

	// Hash the cleartext payload to produce the MAC
	h := c.suite.Hash()
	h.Write(payload)
	mac := h.Sum(nil)[:c.maclen]

	// Embed the payload and MAC into a Point representing the message
	hdr := append(payload, mac...)
	mp,_ := c.suite.Point().Pick(hdr, crypto.RandomStream)

	// Add this to the blinding point we already computed to transmit.
	p.Add(p, mp)
}

func (c *ownedCoder) ownerEncode(payload, payout []byte, p crypto.Point) {

	// XXX trap-encode

	// Pick a fresh random key with which to encrypt the payload
	key := make([]byte, c.keylen)
	crypto.RandomStream.XORKeyStream(key,key)
	//println("key",hex.EncodeToString(key))

	// Encrypt the payload with it
	c.suite.Stream(key).XORKeyStream(payout, payload)

	// Compute a MAC over the encrypted payload
	h := c.suite.Hash()
	h.Write(payout)
	mac := h.Sum(nil)[:c.maclen]
	//println("mac",hex.EncodeToString(mac))

	// Combine the key and the MAC into the Point for this cell header
	hdr := append(key, mac...)
	if len(hdr) != p.PickLen() {
		panic("oops, length of key+mac turned out wrong")
	}
	mp,_ := c.suite.Point().Pick(hdr, crypto.RandomStream)
	//println("encoded data:",hex.EncodeToString(hdr))
	//println("encoded point:",mp.String())

	// Add this to the blinding point we already computed to transmit.
	p.Add(p, mp)
	//println("blinded point:",p.String())
	//println("dat",hex.EncodeToString(payout))
}


///// Trustee methods /////

func (c *ownedCoder) TrusteeCellSize(payloadlen int) int {

	// Trustees produce only the symmetric ciphertext, if any
	return c.symmCellSize(payloadlen)
}

// Setup the trustee side.
// May produce coder configuration info to be passed to the relay,
// which will become available to the RelaySetup() method below.
func (c *ownedCoder) TrusteeSetup(suite crypto.Suite,
				clientstreams []cipher.Stream) []byte {

	// Compute shared secrets
	c.ClientSetup(suite, clientstreams)

	// Release the negation of the composite shared verifiable secret
	// to the relay, so the relay can decode each cell's header.
	c.vkey.Neg(c.vkey)
	return c.vkey.Encode()
}

func (c *ownedCoder) TrusteeEncode(payloadlen int) []byte {

	// Trustees produce only symmetric DC-nets streams
	// for the payload portion of each cell.
	payout := make([]byte, payloadlen)	// XXX trap expansion
	for i := range(c.dcstreams) {
		c.dcstreams[i].XORKeyStream(payout, payout)
	}
	return payout
}


///// Relay methods /////

func (c *ownedCoder) RelaySetup(suite crypto.Suite, trusteeinfo [][]byte) {

	c.commonSetup(suite)

	// Decode the trustees' composite verifiable DC-net secrets
	ntrustees := len(trusteeinfo)
	c.vkeys = make([]crypto.Secret, ntrustees)
	c.vkey = suite.Secret()
	for i := range(c.vkeys) {
		c.vkeys[i] = c.suite.Secret().Decode(trusteeinfo[i])
		c.vkey.Add(c.vkey, c.vkeys[i])
	}

	c.pnull = c.suite.Point().Null()
}

func (c *ownedCoder) DecodeStart(payloadlen int, histoream cipher.Stream) {

	// Compute the composite trustees-side verifiable DC-net unblinder
	// based on the appropriate message history.
	p := c.suite.Point()
	p.Pick(nil, histoream)
	p.Encrypt(p, c.vkey)
	c.point = p

/*
	base := c.suite.Point()
	base.Pick(nil, histoream)
	println("base "+base.String())
	println("vkey "+c.vkey.String())
	println("-vkey "+c.suite.Secret().Neg(c.vkey).String())
	p := c.suite.Point().Encrypt(base, c.vkey)
	println("encr "+p.String())
	c.point = p
	p2 := c.suite.Point().Encrypt(base, c.suite.Secret().Neg(c.vkey))
	println("-encr "+p2.String())
	println("sum "+p2.Add(p2,p).String())
*/

	// Initialize the symmetric ciphertext XOR buffer
	if payloadlen > c.keylen {
		c.xorbuf = make([]byte, payloadlen)
	}
}

func (c *ownedCoder) DecodeClient(slice []byte) {

	// Decode and add in the point in the slice header
	plen := c.suite.PointLen()
	p,err := c.suite.Point().Decode(slice[:plen])
	if (err != nil) {
		println("warning: error decoding point")
	}
	c.point.Add(c.point, p)

	// Combine in the symmetric ciphertext streams
	if c.xorbuf != nil {
		slice = slice[plen:]
		for i := range slice {
			c.xorbuf[i] ^= slice[i]
		}
	}
}

func (c *ownedCoder) DecodeTrustee(slice []byte) {

	// Combine in the trustees' symmetric ciphertext streams
	if c.xorbuf != nil {
		for i := range slice {
			c.xorbuf[i] ^= slice[i]
		}
	}
}

func (c *ownedCoder) DecodeCell() []byte {

	if c.point.Equal(c.pnull) {
		//println("no transmission in cell")
		return nil
	}

	// Decode the header from the decrypted point.
	hdr,err := c.point.Data()
	if err != nil || len(hdr) < c.maclen {
		println("warning: undecipherable cell header")
		return nil	// XXX differentiate from no transmission?
	}
	//println("decoded point:",c.point.String())
	//println("decoded data:",hex.EncodeToString(hdr))

	if c.xorbuf == nil {	// short inline cell
		return c.inlineDecode(hdr)
	} else {		// long payload cell
		return c.ownerDecode(hdr)
	}
}

func (c *ownedCoder) inlineDecode(hdr []byte) []byte {

	// Split the inline payload from the MAC
	datlen := len(hdr) - c.maclen
	dat := hdr[:datlen]
	mac := hdr[datlen:]

	// Check the MAC
	h := c.suite.Hash()
	h.Write(dat)
	check := h.Sum(nil)[:c.maclen]
	if !bytes.Equal(mac, check) {
		println("warning: MAC check failed on inline cell")
		return nil
	}

	return dat
}

func (c *ownedCoder) ownerDecode(hdr []byte) []byte {

	// Split the payload encryption key from the MAC
	keylen := len(hdr) - c.maclen
	if keylen != c.keylen {
		println("warning: wrong size cell encryption key")
		return nil
	}
	key := hdr[:keylen]
	mac := hdr[keylen:]
	//println("key",hex.EncodeToString(key))
	//println("mac",hex.EncodeToString(mac))
	dat := c.xorbuf
	//println("dat",hex.EncodeToString(dat))

	// Check the MAC on the still-encrypted data
	h := c.suite.Hash()
	h.Write(dat)
	check := h.Sum(nil)[:c.maclen]
	if !bytes.Equal(mac, check) {
		println("warning: MAC check failed on out-of-line cell")
		return nil
	}

	// Decrypt and return the payload data
	c.suite.Stream(key).XORKeyStream(dat, dat)
	return dat
}

