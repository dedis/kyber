package dcnet

import (
	"crypto/cipher"
	"dissent/crypto"
)

// Cell encoding, decoding, and accountability interface.
// One instance per series.
// Designed to support multiple alternative cell encoding methods,
// some for single-owner cells (in which only one key-holder transmits),
// others for multi-owner cells (for transmit-request bitmaps for example).
type CellCoder interface {

	///// Common methods /////

	// Compute the client ciphertext size for a given cell payload length,
	// accounting for whatever expansion the cell encoding imposes.
	ClientCellSize(payloadlen int) int

	// Compute the trustee ciphertext size for a given cell payload length,
	// accounting for whatever expansion the cell encoding imposes.
	TrusteeCellSize(payloadlen int) int


	///// Client methods /////

	ClientSetup(suite crypto.Suite, trusteestreams []cipher.Stream)

	// Encode a ciphertext slice for the current cell,
	// transmitting the optional payload if non-nil.
	ClientEncode(payload []byte, payloadlen int,
			histoream cipher.Stream) []byte


	///// Client methods /////

	TrusteeSetup(suite crypto.Suite, clientstreams []cipher.Stream) []byte

	// Encode the trustee's ciphertext slice for the current cell.
	// Can be pre-computed for an interval based on a client-set.
	TrusteeEncode(payloadlen int) []byte


	///// Relay methods /////

	RelaySetup(suite crypto.Suite, trusteeinfo [][]byte)

	// Initialize per-cell decoding state for the next cell
	DecodeStart(payloadlen int, histoream cipher.Stream)

	// Combine a client's ciphertext slice into this cell.
	// This decoding could be done in the background for parallelism;
	// it doesn't have to be finished until DecodeFinal() is called.
	DecodeClient(slice []byte)

	// Same but to combine a trustee's slice into this cell.
	DecodeTrustee(slice []byte)

	// Combine all client and trustee slices provided via DecodeSlice(),
	// to reveal the anonymized plaintext for this cell.
	DecodeCell() []byte
}


type CellFactory func() CellCoder

