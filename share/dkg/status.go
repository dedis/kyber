package dkg

const (
	Success   = true
	Complaint = false
)

type BitSet = map[uint32]bool
type StatusMatrix map[uint32]BitSet

func NewStatusMatrix(dealers []Node, shareHolders []Node, status bool) *StatusMatrix {
	maxDealers = findMaxIndex(dealers)
	maxHolders = findMaxIndex(shareHolders)
	statuses := make(map[uint32]BitSet)
	for _, dealer := range dealers {
		bitset := make(map[uint32]bool)
		for _, holder := range shareHolders {
			bitset[holder.Index] = status
		}
		statuses[dealer.Index] = bitset
	}
	return statuses
}

func (s *StatusMatrix) StatusesForShare(shareIndex uint32) BitSet {
	bt = make(BitSet)
	for dealerIdx, bs := range *s {
		status, ok := bs[shareIndex]
		if !ok {
			panic("index out of range - not supposed to happen")
		}
		bt[dealerIdx] = status
	}
	return bt
}

func (s *StatusMatrix) StatusesOfDealer(dealerIndex uint32) BitSet {
	return (*s)[dealerIndex]
}

// can panic if indexes are not from the original list of nodes
func (s *StatusMatrix) Set(dealer, share uint32, status bool) {
	(*s)[dealer][share] = status
}

func (s *StatusMatrix) SetAll(dealer uint32, status bool) {
	for share := range (*s)[dealer] {
		(*s)[dealer][share] = status
	}
}

func (s *StatusMatrix) AllTrue(dealer uint32) bool {
	for _, status := range (*s)[dealer] {
		if status == Complaint {
			return false
		}
	}
	return true
}

// can panic if indexes are not from the original list of nodes
func (s *StatusMatrix) Get(dealer, share int) bool {
	return s[dealer][share]
}

func findMaxIndex(list []Node) int {
	m := 0
	for _, n := range list {
		if n.Index > m {
			m = n.Index
		}
	}
	return m
}
