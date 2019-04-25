package sign

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type testMask struct {
	numCandidates   int
	numParticipants int
}

func (m testMask) CountTotal() int {
	return m.numCandidates
}

func (m testMask) CountEnabled() int {
	return m.numParticipants
}

func TestPolicy_CompletePolicy(t *testing.T) {
	mask := testMask{
		numCandidates:   4,
		numParticipants: 4,
	}

	policy := CompletePolicy{}
	require.True(t, policy.Check(mask))

	mask.numParticipants = 3
	require.False(t, policy.Check(mask))
}

func TestPolicy_ThresholdPolicy(t *testing.T) {
	mask := testMask{
		numCandidates:   5,
		numParticipants: 2,
	}

	policy := NewThresholdPolicy(3)
	require.False(t, policy.Check(mask))

	mask.numParticipants = 3
	require.True(t, policy.Check(mask))
}
