// Package blake2 provides a flexible implementation of BLAKE2
// that can be used as a hash, sponge, or stream cipher.
package blake2

import (
	"github.com/dedis/crypto/abstract"
)


// BLAKE2b standard Initialization Vector (IV).
var iv = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}


// Create a copy of this SpongeCipher with identical state
func (s *state) Clone() abstract.SpongeCipher {
	c := *s
	return &c
}

// Return the sponge cipher's block size: the minimum granularity
// at which partial, unpadded messages may be processed.
func (s *state) BlockSize() int {
	return 128			// BLAKE2b uses 1024-bit blocks
}

// Return the recommended size of symmetric cryptographic keys
// to obtain the full security from this sponge.
func (s *state) KeyLen() int {
	return 32			// 256-bit keys, 512-bit hash strength
}

func (s *state) crypt(dst,src []byte, more,encrypt bool) {
}

func (s *state) Encrypt(dst,src []byte, more bool) {
	s.crypt(dst,src,bool,true)
}

func (s *state) Decrypt(dst,src []byte, more bool) {
	s.crypt(dst,src,bool,false)
}


// Tree contains parameters for tree hashing. Each node in the tree
// can be hashed concurrently, and incremental changes can be done in
// a Merkle tree fashion.
type Tree struct {
	// Fanout: how many children each tree node has. 0 for unlimited.
	// 1 means sequential mode.
	Fanout uint8
	// Maximal depth of the tree. Beyond this height, nodes are just
	// added to the root of the tree. 255 for unlimited. 1 means
	// sequential mode.
	MaxDepth uint8
	// Leaf maximal byte length, how much data each leaf summarizes. 0
	// for unlimited or sequential mode.
	LeafSize uint32
	// Depth of this node. 0 for leaves or sequential mode.
	NodeDepth uint8
	// Offset of this node within this level of the tree. 0 for the
	// first, leftmost, leaf, or sequential mode.
	NodeOffset uint64
	// Inner hash byte length, in the range [0, 64]. 0 for sequential
	// mode.
	InnerHashSize uint8

	// IsLastNode indicates this node is the last, rightmost, node of
	// a level of the tree.
	IsLastNode bool
}

// Config contains parameters for the hash function that affect its
// output.
type Config struct {
	// Digest byte length, in the range [1, 64]. If 0, default size of 64 bytes is used.
	Size uint8
	// Key is up to 64 arbitrary bytes, for keyed hashing mode. Can be nil.
	Key []byte
	// Salt is up to 16 arbitrary bytes, used to randomize the hash. Can be nil.
	Salt []byte
	// Personal is up to 16 arbitrary bytes, used to make the hash
	// function unique for each application. Can be nil.
	Personal []byte

	// Parameters for tree hashing. Set to nil to use default
	// sequential mode.
	Tree *Tree
}

// New returns a new custom BLAKE2b hash.
//
// If config is nil, uses a 64-byte digest size.
func New(config *Config) *digest {
	d := &digest{
		param: C.blake2b_param{
			digest_length: 64,
			fanout:        1,
			depth:         1,
		},
	}
	if config != nil {
		if config.Size != 0 {
			d.param.digest_length = C.uint8_t(config.Size)
		}
		if len(config.Key) > 0 {
			// let the C library worry about the exact limit; we just
			// worry about fitting into the variable
			if len(config.Key) > 255 {
				panic("blake2b key too long")
			}
			d.param.key_length = C.uint8_t(len(config.Key))
			d.key = config.Key
		}
		salt := (*[C.BLAKE2B_SALTBYTES]byte)(unsafe.Pointer(&d.param.salt[0]))
		copy(salt[:], config.Salt)
		personal := (*[C.BLAKE2B_SALTBYTES]byte)(unsafe.Pointer(&d.param.personal[0]))
		copy(personal[:], config.Personal)

		if config.Tree != nil {
			d.param.fanout = C.uint8_t(config.Tree.Fanout)
			d.param.depth = C.uint8_t(config.Tree.MaxDepth)
			d.param.leaf_length = C.uint32_t(config.Tree.LeafSize)
			d.param.node_offset = C.uint64_t(config.Tree.NodeOffset)
			d.param.node_depth = C.uint8_t(config.Tree.NodeDepth)
			d.param.inner_length = C.uint8_t(config.Tree.InnerHashSize)

			d.isLastNode = config.Tree.IsLastNode
		}
	}
	d.Reset()
	return d
}

// NewBlake2B returns a new 512-bit BLAKE2B hash.
func NewBlake2B() hash.Hash {
	return New(&Config{Size: 64})
}

// NewKeyedBlake2B returns a new 512-bit BLAKE2B hash with the given secret key.
func NewKeyedBlake2B(key []byte) hash.Hash {
	return New(&Config{Size: 64, Key: key})
}

func (*digest) BlockSize() int {
	return 128
}

func (d *digest) Size() int {
	return int(d.param.digest_length)
}

func (d *digest) Reset() {
	d.state = new(C.blake2b_state)
	var key unsafe.Pointer
	if d.param.key_length > 0 {
		key = unsafe.Pointer(&d.key[0])
	}
	if C.blake2b_init_parametrized(d.state, &d.param, key) < 0 {
		panic("blake2: unable to reset")
	}
	if d.isLastNode {
		d.state.last_node = C.uint8_t(1)
	}
}

func (d *digest) Sum(buf []byte) []byte {
	digest := make([]byte, d.Size())
	C.blake2b_final(d.state, (*C.uint8_t)(&digest[0]), C.uint8_t(d.Size()))
	return append(buf, digest...)
}

func (d *digest) Write(buf []byte) (int, error) {
	if len(buf) > 0 {
		C.blake2b_update(d.state, (*C.uint8_t)(&buf[0]), C.uint64_t(len(buf)))
	}
	return len(buf), nil
}


// NewBlake2BStream returns a new stream cipher with the given secret key.
// The stream cipher uses the BLAKE2B core
// with the Salsa/ChaCha stream cipher construction.
func NewBlake2BStream(key []byte) cipher.Stream {
	s := New(&Config{Size: 64, Key: key})
	C.blake2b_final(s.state, nil, 0)	// mix key into hash state
	s.state.buflen = 0			// prepare for stream expansion
	return s
}

func (d *digest) XORKeyStream(dst, src []byte) {
	dl := len(dst)
	if len(src) != dl {
		panic("XORKeyStream: mismatched buffer lengths")
	}
	C.blake2b_stream(d.state, (*C.uint8_t)(&dst[0]), (*C.uint8_t)(&src[0]),
				C.size_t(dl))
}

