package crypto

import (
	"testing"

	"github.com/dedis/crypto/nist"
)

func TestNullPointUnmarshal(t *testing.T) {
	suite := nist.NewAES128SHA256P256()
	pubKey := suite.Point().Null()

	b, _ := pubKey.MarshalBinary()

	rePubKey := suite.Point()
	err := rePubKey.UnmarshalBinary(b)

	if err != nil {
		t.Error(err)
	}

}
