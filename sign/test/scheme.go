package test

import (
	"testing"

	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

// SchemeTesting tests a scheme with simple checks
func SchemeTesting(t *testing.T, s sign.Scheme) {
	t.Run("Regular signing & verifying", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, public := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		err = s.Verify(public, msg, sig)
		require.Nil(tt, err)
	})
	t.Run("Invalid signature", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, public := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		sig[0] ^= 0x01
		if s.Verify(public, msg, sig) == nil {
			tt.Fatal("verification succeeded unexpectedly")
		}
	})
	t.Run("Invalid Key", func(tt *testing.T) {
		msg := []byte("Hello Boneh-Lynn-Shacham")
		private, _ := s.NewKeyPair(random.New())
		sig, err := s.Sign(private, msg)
		require.Nil(tt, err)
		_, public := s.NewKeyPair(random.New())
		if s.Verify(public, msg, sig) == nil {
			tt.Fatal("verification succeeded unexpectedly")
		}
	})
}
