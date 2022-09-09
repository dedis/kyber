// 2022-09-08 submitted at https://github.com/dedis/kyber/issues/472
// kyber/share/dkg/rabin/threshold_test.go
package dkg

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const GOOD int = 0
const BAD int = 1 /* index of dkg to simulate as offline, -1 will disable */

func TestDKGSecretCommits2(t *testing.T) {
	fullExchange2(t)
	dkg := dkgs[GOOD]
	_, err := dkg.SecretCommits()
	assert.Nil(t, err) //"dkg: can't give SecretCommits if deal not certified"
}

func fullExchange2(t *testing.T) {
	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, nbParticipants*nbParticipants)
	for i, dkg := range dkgs {
		if i != BAD {
			deals, err := dkg.Deals()
			require.Nil(t, err)
			for j, d := range deals {
				if j != BAD {
					resp, err := dkgs[j].ProcessDeal(d)
					require.Nil(t, err)
					require.Equal(t, true, resp.Response.Approved)
					resps = append(resps, resp)
				}
			}
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for i, dkg := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == dkg.index {
				continue
			}
			if i != BAD {
				j, err := dkg.ProcessResponse(resp)
				require.Nil(t, err)
				require.Nil(t, j)
			}
		}
	}
	// 3. make sure everyone has the same QUAL set
	for i, dkg := range dkgs {
		if i != BAD {
			dkg.SetTimeout() //line below fails otherwise
			require.True(t, dkg.Certified())
			for j, dkg2 := range dkgs {
				if j != BAD {
					require.True(t, dkg.isInQUAL(dkg2.index))
				}
			}
		}
	}
}
