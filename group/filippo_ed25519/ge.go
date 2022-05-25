package filippo_ed25519

var d = fieldElement{
	-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116,
}

var sqrtM1 = fieldElement{
	-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482,
}

type extendedGroupElement struct {
	X, Y, Z, T fieldElement
}

func (p *extendedGroupElement) ToBytes(s *[32]byte) {
	var recip, x, y fieldElement

	feInvert(&recip, &p.Z)
	feMul(&x, &p.X, &recip)
	feMul(&y, &p.Y, &recip)
	feToBytes(s, &y)
	s[31] ^= feIsNegative(&x) << 7
}

func (p *extendedGroupElement) Zero() {
	feZero(&p.X)
	feOne(&p.Y)
	feOne(&p.Z)
	feZero(&p.T)
}

func (p *extendedGroupElement) FromBytes(s []byte) bool {
	var u, v, v3, vxx, check fieldElement

	if len(s) != 32 {
		return false
	}
	feFromBytes(&p.Y, s)
	feOne(&p.Z)
	feSquare(&u, &p.Y)
	feMul(&v, &u, &d)
	feSub(&u, &u, &p.Z) // y = y^2-1
	feAdd(&v, &v, &p.Z) // v = dy^2+1

	feSquare(&v3, &v)
	feMul(&v3, &v3, &v) // v3 = v^3
	feSquare(&p.X, &v3)
	feMul(&p.X, &p.X, &v)
	feMul(&p.X, &p.X, &u) // x = uv^7

	fePow22523(&p.X, &p.X) // x = (uv^7)^((q-5)/8)
	feMul(&p.X, &p.X, &v3)
	feMul(&p.X, &p.X, &u) // x = uv^3(uv^7)^((q-5)/8)

	feSquare(&vxx, &p.X)
	feMul(&vxx, &vxx, &v)
	feSub(&check, &vxx, &u) // vx^2-u
	if feIsNonZero(&check) == 1 {
		feAdd(&check, &vxx, &u) // vx^2+u
		if feIsNonZero(&check) == 1 {
			return false
		}
		feMul(&p.X, &p.X, &sqrtM1)
	}

	if feIsNegative(&p.X) != (s[31] >> 7) {
		feNeg(&p.X, &p.X)
	}

	feMul(&p.T, &p.X, &p.Y)
	return true
}
