package anon

import (
	"bytes"
	"errors"
	"crypto/hmac"
	"crypto/cipher"
	//"encoding/hex"
	"dissent/crypto"
)


// XXX belongs in crypto package?
func keyPair(suite crypto.Suite, rand cipher.Stream,
		hide bool) (crypto.Point,crypto.Secret,[]byte) {

	x := suite.Secret().Pick(rand)
	X := suite.Point().Mul(nil,x)
	if !hide {
		return X,x,X.Encode()
	}
	Xh := X.(crypto.Hiding)
	for {
		Xb := Xh.HideEncode(rand)	// try to encode as uniform blob
		if Xb != nil {
			return X,x,Xb		// success
		}
		x.Pick(rand)			// try again with a new key
		X.Mul(nil,x)
	}
}

func header(suite crypto.Suite, X crypto.Point, x crypto.Secret,
		Xb,xb []byte, anonymitySet Set) []byte {

	//fmt.Printf("Xb %s\nxb %s\n",
	//		hex.EncodeToString(Xb),hex.EncodeToString(xb))

	// Encrypt the master secret key with each public key in the set
	S := suite.Point()
	hdr := Xb
	for i := range(anonymitySet) {
		Y := anonymitySet[i]
		S.Mul(Y, x)			// compute DH shared secret
		stream := crypto.PointStream(suite, S)
		xc := make([]byte, len(xb))
		stream.XORKeyStream(xc, xb)
		hdr = append(hdr, xc...)
	}
	return hdr
}

// Encrypt a message for reading by any member of an explit anonymity set.
// The caller supplies one or more keys representing the anonymity set.
// If the provided set contains only one public key,
// this reduces to conventional single-receiver public-key encryption.
// 
// If hide is true,
// Encrypt will produce a uniformly random-looking byte-stream,
// which reveals no metadata other than message length
// to anyone unable to decrypt the message.
// The provided crypto.Suite must support
// uniform-representation encoding of public keys for this to work.
//
func Encrypt(suite crypto.Suite, random cipher.Stream, message []byte,
		anonymitySet Set, hide bool) []byte {

	// Choose a keypair and encode its representation
	X,x,Xb := keyPair(suite, random, hide)
	xb := x.Encode()

	// Generate the ciphertext header
	hdr := header(suite, X, x, Xb, xb, anonymitySet)
	// We now know the ciphertext layout
	hdrlen := len(hdr)
	msglen := len(message)
	maclen := suite.KeyLen()
	ciphertext := make([]byte, hdrlen+msglen+maclen)
	copy(ciphertext,hdr)

	// Now encrypt and MAC the message based on the master secret
	stream := crypto.HashStream(suite, xb, nil)
	mackey := crypto.RandomBytes(maclen, stream)
	mac := hmac.New(suite.Hash, mackey)
	stream.XORKeyStream(ciphertext[hdrlen:hdrlen+msglen], message)
	mac.Write(ciphertext[:hdrlen+msglen])
	ciphertext = mac.Sum(ciphertext[:hdrlen+msglen])[:hdrlen+msglen+maclen]
	return ciphertext
}

// Decrypt a message encrypted for a particular anonymity set.
// Returns the cleartext message on success, or an error on failure.
// 
// The caller provides the anonymity set for which the message is intended,
// and the private key corresponding to one of the public keys in the set.
// Decrypt verifies that the message is encrypted correctly for this set -
// in particular, that it could be decrypted by ALL of the listed members -
// before returning successfully with the decrypted message.
// This verification ensures that a malicious sender
// cannot de-anonymize a receiver by constructing a ciphertext incorrectly
// so as to be decryptable by only some members of the set.
// As a side-effect, this verification also ensures plaintext-awareness:
// that is, it is infeasible for a sender to construct any ciphertext
// that will be accepted by the receiver without knowing the plaintext.
// 
func Decrypt(suite crypto.Suite, ciphertext []byte, anonymitySet Set,
		mine int, privateKey crypto.Secret, hide bool) ([]byte,error) {

	// Decode the (supposed) ephemeral public key from the front
	X := suite.Point()
	var Xb []byte
	if hide {
		Xh := X.(crypto.Hiding)
		hidelen := Xh.HideLen()
		if len(ciphertext) < hidelen {
			return nil,errors.New("ciphertext too short")
		}
		X.(crypto.Hiding).HideDecode(ciphertext[:hidelen])
		Xb = ciphertext[:hidelen]
	} else {
		enclen := X.Len()
		if len(ciphertext) < enclen {
			return nil,errors.New("ciphertext too short")
		}
		if err := X.Decode(ciphertext[:enclen]); err != nil {
			return nil,err
		}
		Xb = ciphertext[:enclen]
	}
	Xblen := len(Xb)

	// Decode the (supposed) master secret with our private key
	nkeys := len(anonymitySet)
	if mine < 0 || mine >= nkeys {
		panic("private-key index out of range")
	}
	seclen := suite.SecretLen()
	maclen := suite.KeyLen()
	if len(ciphertext) < Xblen+seclen*nkeys+maclen {
		return nil,errors.New("ciphertext too short")
	}
	S := suite.Point().Mul(X,privateKey)
	stream := crypto.PointStream(suite, S)
	xb := make([]byte, seclen)
	secofs := Xblen + seclen*mine
	stream.XORKeyStream(xb, ciphertext[secofs:secofs+seclen])
	x := suite.Secret()
	if err := x.Decode(xb); err != nil {
		return nil,err
	}

	// Make sure it reproduces the correct ephemeral public key
	Xv := suite.Point().Mul(nil,x)
	if !X.Equal(Xv) {
		return nil,errors.New("invalid ciphertext")
	}

	// Regenerate and check the rest of the header,
	// to ensure that that any of the anonymitySet members could decrypt it
	hdr := header(suite, X, x, Xb, xb, anonymitySet)
	hdrlen := len(hdr)
	if hdrlen != Xblen+seclen*nkeys {
		panic("wrong header size")
	}
	if !bytes.Equal(hdr, ciphertext[:hdrlen]) {
		return nil,errors.New("invalid ciphertext")
	}
	msglo := hdrlen
	msghi := len(ciphertext)-maclen

	// Check the MAC over the whole ciphertext
	stream = crypto.HashStream(suite, xb, nil)
	mac := hmac.New(suite.Hash, crypto.RandomBytes(maclen, stream))
	mac.Write(ciphertext[:msghi])
	macbuf := mac.Sum(nil)
	if !hmac.Equal(ciphertext[msghi:],macbuf[:maclen]) {
		return nil,errors.New("invalid ciphertext: failed MAC check")
	}

	// Decrypt and return the message
	message := ciphertext[msglo:msghi]
	stream.XORKeyStream(message, message)
	return message,nil
}

