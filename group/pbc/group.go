package pbc

import "gopkg.in/dedis/crypto.v0/abstract"

// Group interface extension to create pairing-capable points.
type PairingGroup interface {
	abstract.Group // Standard Group operations

	PairingPoint() PairingPoint // Create new pairing-capable Point
}

// Point interface extension for a point in a pairing target group (GT),
// which supports the Pairing operation.
type PairingPoint interface {
	abstract.Point // Standard Point operations

	// Compute the pairing of two points p1 and p2,
	// which must be in the associated groups G1 and G2 respectively.
	Pairing(p1, p2 abstract.Point) abstract.Point
}
