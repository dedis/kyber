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

// Simple DC-net encoder providing no disruption or equivocation protection,
// for experimentation and baseline performance evaluations.
func SimpleCoderFactory() CellCoder {
	return new(simpleCoder)
}


///// Client methods /////

func (c *simpleCoder) ClientCellSize(payloadlen int) int {
	return payloadlen	// no expansion
}

func (c *simpleCoder) ClientSetup(suite crypto.Suite,
				peerstreams []cipher.Stream) {
	c.suite = suite

	// Use the provided master streams to seed
	// a pseudorandom DC-nets substream shared with each peer.
	npeers := len(peerstreams)
	c.dcstreams = make([]cipher.Stream, npeers)
	for j := range(peerstreams) {
		c.dcstreams[j] = crypto.SubStream(suite, peerstreams[j])
	}
}

func (c *simpleCoder) ClientEncode(payload []byte, payloadlen int,
				histoream cipher.Stream) []byte {

	if payload == nil {
		payload = make([]byte, payloadlen)
	}
	for i := range(c.dcstreams) {
		c.dcstreams[i].XORKeyStream(payload, payload)
	}
	return payload
}


///// Trustee methods /////

func (c *simpleCoder) TrusteeCellSize(payloadlen int) int {
	return payloadlen	// no expansion
}

func (c *simpleCoder) TrusteeSetup(suite crypto.Suite,
				peerstreams []cipher.Stream) []byte {
	c.ClientSetup(suite, peerstreams)	// no difference
	return nil
}

func (c *simpleCoder) TrusteeEncode(payloadlen int) []byte {
	return c.ClientEncode(nil, payloadlen, nil)	// no difference
}


///// Relay methods /////

func (c *simpleCoder) RelaySetup(suite crypto.Suite, trusteeinfo [][]byte) {
	// nothing to do
}

func (c *simpleCoder) DecodeStart(payloadlen int, histoream cipher.Stream) {

	c.xorbuf = make([]byte, payloadlen)
}

func (c *simpleCoder) DecodeClient(slice []byte) {

	for i := range slice {
		c.xorbuf[i] ^= slice[i]
	}
}

func (c *simpleCoder) DecodeTrustee(slice []byte) {

	c.DecodeClient(slice)	// same
}

func (c *simpleCoder) DecodeCell() []byte {

	return c.xorbuf
}

