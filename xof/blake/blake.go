package blake

import (
	"github.com/dedis/kyber"
	"golang.org/x/crypto/blake2b"
)

type xof struct {
	impl blake2b.XOF
	key  []byte
}

// New creates a new XOF using the Blake2b hash.
func New(seed []byte) kyber.XOF {
	b, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed)
	return &xof{impl: b}
}

func (x *xof) KeySize() int {
	return blake2b.BlockSize
}

func (x *xof) Clone() kyber.XOF {
	return &xof{impl: x.impl.Clone()}
}

func (x *xof) Read(dst []byte) (int, error) {
	return x.impl.Read(dst)
}

func (x *xof) Write(src []byte) (int, error) {
	return x.impl.Write(src)
}

func (x *xof) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too short")
	}
	if len(x.key) < len(src) {
		x.key = make([]byte, len(src))
	}

	n, err := x.Read(x.key)
	if err != nil {
		panic("blake xof error: " + err.Error())
	}
	if n != len(x.key) {
		panic("short read on key")
	}

	for i := range src {
		dst[i] = src[i] ^ x.key[i]
	}
}
