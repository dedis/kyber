package bigmod

import "fmt"

func (x *Nat) CmpGeq(y *Nat) Choice {
	return Choice(x.cmpGeq(y))
}

type Choice uint

func Not(c Choice) Choice { return Choice(not(choice(c))) }

const Yes = Choice(1)
const No = Choice(0)

// CtMask is all 1s if on is yes, and all 0s otherwise.
func CtMask(on Choice) uint { return ctMask(choice(on)) }

// CtEq returns 1 if x == y, and 0 otherwise. The execution time of this
// function does not depend on its inputs.
func CtEq(x, y uint) Choice {
	return Choice(ctEq(x, y))
}

func (x *Nat) Assign(on Choice, y *Nat) *Nat {
	return x.assign(choice(on), y)
}

func (x *Nat) Set(y *Nat) *Nat { return x.set(y) }

func NewModulusFromNat(n *Nat) (*Modulus, error) {
	return newModulus(n)
}

// todo check this
func (x *Nat) BitLenAnnounced() int {
	return len(x.limbs) * _W
}

func LimbsSizeInBytes() int {
	return _S
}

func (x *Nat) Bit(i int) uint {
	fmt.Println(x.limbs)
	return x.limbs[i/64] >> (uint(i) % 64) & 1
}
