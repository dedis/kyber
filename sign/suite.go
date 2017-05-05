package sign

import "hash"

type Suite interface {
	Group
	Hash() hash.Hash
}
