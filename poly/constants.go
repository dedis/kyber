package poly

import ()

const (
	CHECK_ON = iota
	CHECK_OFF
)

// This constants is used to dertermine if for a given state,
// when we call RevealShare, we should check if the state has received enough
// signatures (valid proof) to reveal a share. This check is originally done in
// promise.go but is not a requirement for now at least in the joint.go +
// schnorr.go
var REVEAL_SHARE_CHECK int = CHECK_ON
