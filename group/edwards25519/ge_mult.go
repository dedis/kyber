// +build !vartime

package edwards25519

func geScalarMultVartime(h *extendedGroupElement, a *[32]byte,
	A *extendedGroupElement) {
	panic("geScalarMultVartime should never be called with build tags !vartime")
}
