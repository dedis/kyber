package padding

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	dedis "github.com/dedis/crypto/cipher"
	"github.com/dedis/crypto/cipher/norx"
	"io/ioutil"
	"strconv"
	"testing"
)

//The same things will need to be tested for most of the following functions.

var tests = []struct {
	test                                    int
	msgbits, leakbits, zerobits, paddinglen uint64
	padded                                  bool
}{
	//test a power of 2(2^20)
	{1048576, 21, 5, 16, 0, true},
	//power of 2 plus 1
	{1048577, 21, 5, 16, 65535, false},
	//power of 2 minus 1
	{1048575, 20, 5, 15, 1, false},
	//smallest possible cases.
	{1, 1, 0, 1, 1, false},
	{2, 2, 1, 1, 0, true},
	{3, 2, 1, 1, 1, false},
	{4, 3, 2, 1, 0, true},
	//random cases
	{98723, 17, 5, 12, 3677, false},
}

func TestGetMsgBits(t *testing.T) {
	fmt.Println("Testing GetMsgBits")
	for _, v := range tests {
		if GetMsgBits(v.test, 0) != v.msgbits {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, GetMsgBits(v.test, 0), v.msgbits)
		}
	}
}

func TestGetLeakBits(t *testing.T) {
	fmt.Println("Testing GetLeakBits")
	for _, v := range tests {
		if GetLeakBits(v.test, 0) != v.leakbits {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, GetLeakBits(v.test, 0), v.leakbits)
		}
	}
}

func TestGetZeroBits(t *testing.T) {
	fmt.Println("Testing GetZeroBits")
	for _, v := range tests {
		if GetZeroBits(v.test, 0) != v.zerobits {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, GetZeroBits(v.test, 0), v.zerobits)
		}
	}
}

func TestGetPaddingLen(t *testing.T) {
	fmt.Println("Testing GetPaddingLen")
	for _, v := range tests {
		if GetPaddingLen(v.test, 0) != v.paddinglen {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, GetPaddingLen(v.test, 0), v.paddinglen)
		}
	}
}

func TestCheckZeroBits(t *testing.T) {
	fmt.Println("Testing CheckZeroBits")
	for _, v := range tests {
		if CheckZeroBits(v.test) != v.padded {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, CheckZeroBits(v.test), v.padded)
		}
	}
}

func TestGeneratePadding(t *testing.T) {
	fmt.Println("Testing GeneratePadding")
	for _, v := range tests {
		if len(GeneratePadding(uint64(v.test))) != v.test {
			fmt.Printf("Error on %v, computed:%v correct:%v\n",
				v.test, len(GeneratePadding(uint64(v.test))), v.test)
		}
	}
}

//Tests the padding with aes-gcm
func TestAESGCM(t *testing.T) {
	fmt.Println("Testing padding with AESGCM")
	//need to generate key.
	key, _ := hex.DecodeString("9a4fea86a621a91ab371e492457796c0")
	//initialize pt from file
	pt, err := ioutil.ReadFile("testmessage.txt")
	if err != nil {
		fmt.Println(err)

	}
	ad := []byte("1234567890123456123123123123123123")
	//nonce by default needs to be 12 bytes
	nonce := []byte("123456781238")

	aes, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		fmt.Println(err)
	}
	//aesgcm adds 16 bytes to the end of the encrpyted message. These 16 bytes are the authentication tag.
	//And an additional 8 bytes for the overhead of how we are padding it.
	x := GetLeakBits(len(pt), 16+8)
	y := GetMsgBits(len(pt), 16+8)
	z := GetZeroBits(len(pt), 16+8)
	p := GetPaddingLen(len(pt), 16+8)
	fmt.Println("Msg w/ static overhead: ", len(pt)+16+8, " Bits to store len: ",
		y, " Leak Bits: ", x, " ZeroBits: ", z)

	fmt.Println("Padding needed: ", p)
	fmt.Printf("Increase in message size caused by the padding (padding+len+oh)/len: %.4f\n", ((float64(p+24) + float64(len(pt))) / float64(len(pt))))

	//PadGeneric takes in a pt, and the overhead that encryption scheme will add. It returns a p' with the format [Amount of padding(8 bytes)][original pt][padding]

	paddedpt := PadGeneric(pt, 16)
	//fmt.Println(pt)
	//Encrypt the plaintext with aesgcm
	ct := aesgcm.Seal(nil, nonce, paddedpt, ad)
	//check if our ct is correctly padded
	if CheckZeroBits(len(ct)) {
		fmt.Println("The ciphertext is of a correct length")
		fmt.Println("Length is ", len(ct))
		fmt.Println(strconv.FormatUint(uint64(len(ct)), 2))
		fmt.Println("Length of original pt: ", len(pt))
		fmt.Println(strconv.FormatUint(uint64(len(pt)), 2))

	} else {
		fmt.Println("Error: ciphertext was not correctly padded.")
	}
	//decrypt the ct
	paddedpt, _ = aesgcm.Open(nil, nonce, ct, ad)
	//unpad the pt
	paddedpt = UnPadGeneric(paddedpt)
	//check if the message was recovered correctly.
	if bytes.Equal(pt, paddedpt) {
		fmt.Println("The message was decrypted, and unpadded successfully ")
	}
}

//Using an implementation from the dedis crypto library(github.com/dedis/crypto).
func TestNorxAEAD(t *testing.T) {
	//Info on norx from https://norx.io/data/norx.pdf
	//Code works while not following input parameters
	//Guessing wordsize is 64 bits(options are 32 or 64)

	//So key size should be 4*8 bytes
	//nonce size should be 2*8 bytes long
	//I am not exactly sure on the implementation. As it can work with keys, and nonces that
	//don't follow the guidelines.
	//Possibly need to account for sending the nonce as well as the message in some cases.
	key := []byte("12345678123456781234567812345678")
	ciph := norx.NewCipher(key)
	aead := dedis.NewAEAD(ciph)
	dst := []byte("")
	pt := []byte("this is the pt")
	//AT should be 256 or 128 I think
	data := []byte("12345678123456781234567812345678")
	nonce := []byte("1234567812345678")

	//Test for a lot of values
	for i := 0; i < 50; i++ {
		ptpad := PadGeneric(pt, 24)
		ct := aead.Seal(dst, nonce, ptpad, data)
		//	fmt.Println("Length of ct is ", len(ct))
		//	fmt.Println(strconv.FormatUint(uint64(len(ct)), 2))
		pt2, _ := aead.Open(dst, nonce, ct, data)
		pt2 = UnPadGeneric(pt2)
		if !bytes.Equal(pt, pt2) {
			fmt.Println("Error with adding and removing padding from message")
		}
		//	fmt.Println(string(pt))
		//	fmt.Println(len(ct), len(pt2), len(pt), len(ct)-len(pt))
		pt = append(pt, byte(0))
	}

	pt, err := ioutil.ReadFile("testmessage.txt")
	if err != nil {
		fmt.Println(err)
	}
	//Seems to be a constant size of 24 bytes added.
	ptpad := PadGeneric(pt, 24)
	ct2 := aead.Seal(dst, nonce, ptpad, data)
	fmt.Println("Length of ct is ", len(ct2))
	fmt.Println(strconv.FormatUint(uint64(len(ct2)), 2))
	pt3, _ := aead.Open(dst, nonce, ct2, data)
	pt3 = UnPadGeneric(pt3)
	if !bytes.Equal(pt, pt3) {
		fmt.Println("Error with adding and removing padding from message")
	}
	fmt.Println(len(ct2), len(pt3), len(pt))

}
