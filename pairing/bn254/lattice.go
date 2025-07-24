//go:build !constantTime

package bn254

import (
	"go.dedis.ch/kyber/v4/compatible"
)

var half = new(compatible.Int).Rsh(Order, 1)

var curveLattice = &lattice{
	vectors: [][]*compatible.Int{
		{bigFromBase10("147946756881789319000765030803803410728"), bigFromBase10("147946756881789319010696353538189108491")},
		{bigFromBase10("147946756881789319020627676272574806254"), bigFromBase10("-147946756881789318990833708069417712965")},
	},
	inverse: []*compatible.Int{
		bigFromBase10("147946756881789318990833708069417712965"),
		bigFromBase10("147946756881789319010696353538189108491"),
	},
	det: bigFromBase10("43776485743678550444492811490514550177096728800832068687396408373151616991234"),
}

//nolint:lll,unused // maybe useful
var targetLattice = &lattice{
	vectors: [][]*compatible.Int{
		{bigFromBase10("9931322734385697761"), bigFromBase10("9931322734385697761"), bigFromBase10("9931322734385697763"), bigFromBase10("9931322734385697764")},
		{bigFromBase10("4965661367192848881"), bigFromBase10("4965661367192848881"), bigFromBase10("4965661367192848882"), bigFromBase10("-9931322734385697762")},
		{bigFromBase10("-9931322734385697762"), bigFromBase10("-4965661367192848881"), bigFromBase10("4965661367192848881"), bigFromBase10("-4965661367192848882")},
		{bigFromBase10("9931322734385697763"), bigFromBase10("-4965661367192848881"), bigFromBase10("-4965661367192848881"), bigFromBase10("-4965661367192848881")},
	},
	inverse: []*compatible.Int{
		bigFromBase10("734653495049373973658254490726798021314063399421879442165"),
		bigFromBase10("147946756881789319000765030803803410728"),
		bigFromBase10("-147946756881789319005730692170996259609"),
		bigFromBase10("1469306990098747947464455738335385361643788813749140841702"),
	},
	det: new(compatible.Int).Set(Order),
}

type lattice struct {
	vectors [][]*compatible.Int
	inverse []*compatible.Int
	det     *compatible.Int
}

// decompose takes a scalar mod Order as input and finds a short, positive decomposition of it wrt to the lattice basis.
func (l *lattice) decompose(k *compatible.Int) []*compatible.Int {
	n := len(l.inverse)

	// Calculate closest vector in lattice to <k,0,0,...> with Babai's rounding.
	c := make([]*compatible.Int, n)
	for i := 0; i < n; i++ {
		c[i] = new(compatible.Int).Mul(k, l.inverse[i])
		round(c[i], l.det)
	}

	// Transform vectors according to c and subtract <k,0,0,...>.
	out := make([]*compatible.Int, n)
	temp := new(compatible.Int)

	for i := 0; i < n; i++ {
		out[i] = new(compatible.Int)

		for j := 0; j < n; j++ {
			temp.Mul(c[j], l.vectors[j][i])
			out[i].Add(out[i], temp)
		}

		out[i].Neg(out[i])
		out[i].Add(out[i], l.vectors[0][i]).Add(out[i], l.vectors[0][i])
	}
	out[0].Add(out[0], k)

	return out
}

func (l *lattice) Precompute(add func(i, j uint)) {
	n := uint(len(l.vectors))
	total := uint(1) << n

	for i := uint(0); i < n; i++ {
		for j := uint(0); j < total; j++ {
			if (j>>i)&1 == 1 {
				add(i, j)
			}
		}
	}
}

func (l *lattice) Multi(scalar *compatible.Int) []uint8 {
	decomp := l.decompose(scalar)

	maxLen := 0
	for _, x := range decomp {
		if x.BitLen() > maxLen {
			maxLen = x.BitLen()
		}
	}

	out := make([]uint8, maxLen)
	for j, x := range decomp {
		for i := 0; i < maxLen; i++ {
			out[i] += uint8(x.Bit(i)) << uint(j)
		}
	}

	return out
}

// round sets num to num/denom rounded to the nearest integer.
func round(num, denom *compatible.Int) {
	r := new(compatible.Int)
	num.DivMod(num, denom, r)

	// todo CondAssignment
	if r.Cmp(half) == 1 {
		num.Add(num, compatible.NewInt(1))
	}
}
