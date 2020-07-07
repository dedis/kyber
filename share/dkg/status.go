package dkg

import (
	"fmt"
	"sort"
	"strings"
)

const (
	Success   = true
	Complaint = false
)

type BitSet map[uint32]bool
type StatusMatrix map[uint32]BitSet

func NewStatusMatrix(dealers []Node, shareHolders []Node, status bool) *StatusMatrix {
	statuses := make(map[uint32]BitSet)
	for _, dealer := range dealers {
		bitset := make(map[uint32]bool)
		for _, holder := range shareHolders {
			bitset[holder.Index] = status
		}
		statuses[dealer.Index] = bitset
	}
	sm := StatusMatrix(statuses)
	return &sm
}

func (s *StatusMatrix) StatusesForShare(shareIndex uint32) BitSet {
	bt := make(BitSet)
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

func (s *StatusMatrix) CompleteSuccess() bool {
	for dealer := range *s {
		if !s.AllTrue(dealer) {
			return false
		}
	}
	return true
}

// can panic if indexes are not from the original list of nodes
func (s *StatusMatrix) Get(dealer, share uint32) bool {
	return (*s)[dealer][share]
}

func (s *StatusMatrix) String() string {
	// get dealer indexes
	dealerIdx := make([]int, 0, len(*s))
	for didx := range *s {
		dealerIdx = append(dealerIdx, int(didx))
	}
	// get share holder indexes
	sharesIdx := make([]int, 0, len((*s)[uint32(dealerIdx[0])]))
	for sidx := range (*s)[uint32(dealerIdx[0])] {
		sharesIdx = append(sharesIdx, int(sidx))
	}
	sort.Ints(dealerIdx)
	sort.Ints(sharesIdx)
	var str = ""
	for _, dealerIndex := range dealerIdx {
		var statuses []string
		for _, shareIndex := range sharesIdx {
			status := (*s)[uint32(dealerIndex)][uint32(shareIndex)]
			var st string
			if status {
				st = fmt.Sprintf(" %d: ok", shareIndex)
			} else {
				st = fmt.Sprintf(" %d: no", shareIndex)
			}
			statuses = append(statuses, st)
		}
		str += fmt.Sprintf("dealer %d: [ %s ]\n", dealerIndex, strings.Join(statuses, ","))
	}
	return str
}

func findMaxIndex(list []Node) int {
	m := 0
	for _, n := range list {
		if n.Index > uint32(m) {
			m = int(n.Index)
		}
	}
	return m
}

func (b BitSet) LengthComplaints() int {
	var count = 0
	for _, status := range b {
		if status == Complaint {
			count++
		}
	}
	return count
}
