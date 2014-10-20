package anon

import (
	"errors"
	"crypto/hmac"
	"crypto/cipher"
	"crypto/subtle"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
)


// XXX belongs in crypto package?
func keyPair(suite abstract.Suite, rand cipher.Stream,
		hide bool) (abstract.Point,abstract.Secret,[]byte) {

	x := suite.Secret().Pick(rand)
	X := suite.Point().Mul(nil,x)
	if !hide {
		return X,x,X.Encode()
	}
	Xh := X.(abstract.Hiding)
	for {
		Xb := Xh.HideEncode(rand)	// try to encode as uniform blob
		if Xb != nil {
			return X,x,Xb		// success
		}
		x.Pick(rand)			// try again with a new key
		X.Mul(nil,x)
	}
}

func header(suite abstract.Suite, X abstract.Point, x abstract.Secret,
		Xb,xb []byte, anonymitySet Set) []byte {

	//fmt.Printf("Xb %s\nxb %s\n",
	//		hex.EncodeToString(Xb),hex.EncodeToString(xb))

	// Encrypt the master secret key with each public key in the set
	S := suite.Point()
	hdr := Xb
	for i := range(anonymitySet) {
		Y := anonymitySet[i]
		S.Mul(Y, x)			// compute DH shared secret
		stream := abstract.PointStream(suite, S)
		xc := make([]byte, len(xb))
		stream.XORKeyStream(xc, xb)
		hdr = append(hdr, xc...)
	}
	return hdr
}

// Create and encrypt a fresh key decryptable only by the given receivers.
// Returns the secret key and the ciphertext.
func encryptKey(suite abstract.Suite, rand cipher.Stream,
		anonymitySet Set, hide bool) (k,c []byte) {

	// Choose a keypair and encode its representation
	X,x,Xb := keyPair(suite, rand, hide)
	xb := x.Encode()

	// Generate the ciphertext header
	return xb,header(suite, X, x, Xb, xb, anonymitySet)
}

// Decrypt and verify a key encrypted via encryptKey.
// On success, returns the key and the length of the decrypted header.
func decryptKey(suite abstract.Suite, ciphertext []byte, anonymitySet Set,
		mine int, privateKey abstract.Secret,
		hide bool) ([]byte,int,error) {

	// Decode the (supposed) ephemeral public key from the front
	X := suite.Point()
	var Xb []byte
	if hide {
		Xh := X.(abstract.Hiding)
		hidelen := Xh.HideLen()
		if len(ciphertext) < hidelen {
			return nil,0,errors.New("ciphertext too short")
		}
		X.(abstract.Hiding).HideDecode(ciphertext[:hidelen])
		Xb = ciphertext[:hidelen]
	} else {
		enclen := X.Len()
		if len(ciphertext) < enclen {
			return nil,0,errors.New("ciphertext too short")
		}
		if err := X.Decode(ciphertext[:enclen]); err != nil {
			return nil,0,err
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
	if len(ciphertext) < Xblen+seclen*nkeys {
		return nil,0,errors.New("ciphertext too short")
	}
	S := suite.Point().Mul(X,privateKey)
	stream := abstract.PointStream(suite, S)
	xb := make([]byte, seclen)
	secofs := Xblen + seclen*mine
	stream.XORKeyStream(xb, ciphertext[secofs:secofs+seclen])
	x := suite.Secret()
	if err := x.Decode(xb); err != nil {
		return nil,0,err
	}

	// Make sure it reproduces the correct ephemeral public key
	Xv := suite.Point().Mul(nil,x)
	if !X.Equal(Xv) {
		return nil,0,errors.New("invalid ciphertext")
	}

	// Regenerate and check the rest of the header,
	// to ensure that that any of the anonymitySet members could decrypt it
	hdr := header(suite, X, x, Xb, xb, anonymitySet)
	hdrlen := len(hdr)
	if hdrlen != Xblen+seclen*nkeys {
		panic("wrong header size")
	}
	if subtle.ConstantTimeCompare(hdr, ciphertext[:hdrlen]) == 0 {
		return nil,0,errors.New("invalid ciphertext")
	}

	return xb,hdrlen,nil
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
// The provided abstract.Suite must support
// uniform-representation encoding of public keys for this to work.
//
func Encrypt(suite abstract.Suite, rand cipher.Stream, message []byte,
		anonymitySet Set, hide bool) []byte {

	xb,hdr := encryptKey(suite, rand, anonymitySet, hide)

	// We now know the ciphertext layout
	hdrlen := len(hdr)
	msglen := len(message)
	maclen := suite.KeyLen()
	ciphertext := make([]byte, hdrlen+msglen+maclen)
	copy(ciphertext,hdr)

	// Now encrypt and MAC the message based on the master secret
	stream := abstract.HashStream(suite, xb, nil)
	mackey := random.Bytes(maclen, stream)
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
func Decrypt(suite abstract.Suite, ciphertext []byte, anonymitySet Set,
		mine int, privateKey abstract.Secret, hide bool) ([]byte,error) {

	// Decrypt and check the encrypted key-header.
	xb,hdrlen,err := decryptKey(suite, ciphertext, anonymitySet,
					mine, privateKey, hide)
	if err != nil {
		return nil,err
	}

	// Determine the message layout
	maclen := suite.KeyLen()
	if len(ciphertext) < hdrlen+maclen {
		return nil,errors.New("ciphertext too short")
	}
	msglo := hdrlen
	msghi := len(ciphertext)-maclen

	// Check the MAC over the whole ciphertext
	stream := abstract.HashStream(suite, xb, nil)
	mac := hmac.New(suite.Hash, random.Bytes(maclen, stream))
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

