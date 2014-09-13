package nego

import (
	"fmt"
	"dissent/crypto"
)


// Pick a uint32 uniformly at random
func randUint32() uint32 {
	return crypto.RandomUint32(crypto.RandomStream)
}

// Pick a random height for a new skip-list node from a suitable distribution.
func skipHeight() int {
	height := 1
	for v := randUint32() | (1<<31); v & 1 == 0; v >>= 1 {
		height++
	}
	return height
}

type skipNode struct {
	lo,hi int
	suc []*skipNode
	obj interface{}
}

// Skip-list reservation structure
type skipLayout struct {
	head []*skipNode
}

func (sl *skipLayout) reset() {
	sl.head = make([]*skipNode, 1)		// minimum stack height
}

func (sl *skipLayout) reserve(lo,hi int, excl bool, obj interface{}) bool {

	// An iterator is a stack of pointers to next pointers, one per level
	pos := make([]**skipNode, len(sl.head))
	for i := range(pos) {
		pos[i] = &sl.head[i]
	}

	// Find the position past all nodes strictly before our interest area
	for i := len(pos)-1; i >= 0; i-- {
		for n := *pos[i]; n != nil && n.hi <= lo; n = *pos[i] {
			// Advance past n at all levels up through i
			for j := i; j >= 0; j-- {
				pos[j] = &n.suc[j]
			}
		}
	}

	// Can we get an exclusive reservation?
	suc := *pos[0]
	gotExcl := true
	if suc != nil && suc.lo < hi {		// suc overlaps what we want?
		if excl {
			return false		// excl required but can't get
		}
		gotExcl = false
	}

	// Reserve any parts of this extent not already reserved.
	for lo < hi {
		suc = *pos[0]
		if suc != nil && suc.lo <= lo {
			// suc occupies first part of our region, so skip it
			lo = suc.hi
			for j := len(suc.suc)-1; j >= 0; j-- {
				pos[j] = &suc.suc[j]
			}
			continue
		}

		// How big of a reservation can we insert here?
		inshi := hi
		if suc != nil && suc.lo < inshi {
			inshi = suc.lo	// end at start of next existing region
		}
		if lo >= inshi {
			panic("trying to insert empty reservation")
		}
		//fmt.Printf("inserting [%d-%d]\n", lo,hi)

		// Create a new node with a suitably random stack height
		nsuc := make([]*skipNode,skipHeight())
		n := skipNode{lo,inshi,nsuc,obj}

		// Insert the new node at all appropriate levels
		for i := range(nsuc) {
			if i == len(pos) {
				// base node's stack not high enough, extend it
				sl.head = append(sl.head, nil)
				pos = append(pos, &sl.head[i])
			}
			nsuc[i] = *pos[i]
			*pos[i] = &n
			pos[i] = &nsuc[i]
		}
		lo = inshi
	}

	return gotExcl
}

func (sl *skipLayout) dump() {

	pos := make([]**skipNode, len(sl.head))
	//fmt.Printf("Skip-list levels: %d\n", len(pos))
	for i := range(pos) {
		pos[i] = &sl.head[i]
		//fmt.Printf(" H%d: %p\n", i, *pos[i])
	}
	for n := *pos[0]; n != nil; n = *pos[0] {
		fmt.Printf("%p [%d-%d] level %d: %s\n",
				n, n.lo, n.hi, len(n.suc),
				n.obj.(dumpable).String())
		for j := range(n.suc) {		// skip-list invariant check
			//fmt.Printf(" S%d: %p\n", j, n.suc[j])
			if *pos[j] != n {
				panic("bad suc pointer")
			}
			pos[j] = &n.suc[j]
		}
	}
	for i := range(pos) {
		n := *pos[i]
		if n != nil {
			panic("orphaned skip-node: "+n.obj.(dumpable).String())
		}
	}
}

