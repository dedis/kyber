// Simple DC-net encoder providing no disruption or equivocation protection,
// for experimentation and baseline performance evaluations.
package dcnet

import (
	"crypto/cipher"
	"dissent/crypto"
)

type simpleCoder struct {
	suite crypto.Suite

	// Pseudorandom DC-nets streams shared with each peer.
	// On clients, there is one DC-nets stream per trustee.
	// On trustees, there ois one DC-nets stream per client.
	dcstreams []cipher.Stream

	xorbuf []byte
}

func SimpleCoderFactory() CellCoder {
	return new(simpleCoder)
}


///// Client and Trustee methods /////

func (c *simpleCoder) Setup(suite crypto.Suite, peerstreams []cipher.Stream) {
	c.suite = suite

	// Use the provided master streams to seed
	// a pseudorandom DC-nets substream shared with each peer.
	npeers := len(peerstreams)
	c.dcstreams = make([]cipher.Stream, npeers)
	for j := range(peerstreams) {
		c.dcstreams[j] = crypto.SubStream(suite, peerstreams[j])
	}
}

func (c *simpleCoder) EncodeSlice(payload []byte, cellsize int) []byte {

	if payload == nil {
		payload = make([]byte, cellsize)
	}
	for i := range(c.dcstreams) {
		c.dcstreams[i].XORKeyStream(payload, payload)
	}
	return payload
}


///// Relay methods /////

func (c *simpleCoder) DecodeStart(cellsize int) {

	c.xorbuf = make([]byte, cellsize)
}

func (c *simpleCoder) DecodeSlice(slice []byte) {

	for i := range slice {
		c.xorbuf[i] ^= slice[i]
	}
}

func (c *simpleCoder) DecodeCell() []byte {

	return c.xorbuf
}

