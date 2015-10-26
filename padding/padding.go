package padding

import (
	"bytes"
	"encoding/binary"
	"math"
)

//overhead to encode the amount of padding, could be reduced through a more complex way.
const PADLEN = 8

//Returns the number of bits required to represent the length of the message and the overhead.
func GetMsgBits(msg []byte, overhead int) uint64 {
	//Plus one because if the message is a power of 2 it would give a length of 1 less then is needed to store it. A message of 8 bytes, needs 4 bits. But log_2(8)=3
	return uint64(math.Ceil(math.Log2(float64(len(msg)+overhead) + 1)))
}

//Returns the number of leak bits.
func GetLeakBits(msg []byte, overhead int) uint64 {
	return uint64(math.Ceil(math.Log2(float64(GetMsgBits(msg, overhead)))))
}

//Returns the number of bits that need to be zeroed.
func GetZeroBits(msg []byte, overhead int) uint64 {
	return GetMsgBits(msg, overhead) - GetLeakBits(msg, overhead)
}

//Returns how many bytes of padding need to be added
//Works by forcing all bits higher then the 0 bits to 1, then inverting and adding 1.
//Another way to do this would just be look at each bit 1 at a time
//For zeroBits
// sum+= l & (1<<i)
//Code so that if l&(1<<i) is 0 it adds 2^i, otherwise nothing
func GetPaddingLen(msg []byte, overhead int) uint64 {
	l := uint64(len(msg) + overhead)
	zb := GetZeroBits(msg, overhead)

	var i, mask uint64
	//Generate a mask that we can use to isolate the first zb bits of the length.
	for i = 0; i < zb; i++ {
		mask |= (1 << i)
	}

	//inver the mask
	mask = ^mask

	//Or the mask with our length. Now all non zero bits are 1
	l |= mask
	//invert l, now we have the ^l, ^l + l will give us only 1s So if we add 1 to that we get 0 in all of the zero bits, and the next largest bit will be a 1.
	l = ^l
	l = l + 1
	//This is the case where all of the zero bits are already 0.
	if float64(l) == math.Pow(2, float64(zb)) {
		l = 0
	}
	return l

}

//Function that checks if a message is padded correctly
func CheckZeroBits(msg []byte) bool {
	l := uint64(len(msg))
	zb := GetZeroBits(msg, 0)
	var i, mask uint64
	for i = 0; i < zb; i++ {
		mask |= (1 << i)
	}
	mask = ^mask

	l |= mask
	l = ^l
	l = l + 1
	//case were the message is padded correctly( all bits are 0 -> all are 1 -> +1 = zb^2
	if float64(l) == math.Pow(2, float64(zb)) {
		l = 0
	}
	if l == 0 {
		return true
	}
	return false

}

//generates padding, can be later modified if something else is better.
//There is also probably a more efficient way to generate it.
func GeneratePadding(p uint64) []byte {
	b := make([]byte, p)
	var i uint64
	for i = 0; i < p; i++ {
		b[i] = 51 //random choice
	}
	return b
}

//To call these you need to know the overhead that the encryption process will add.
func PadGeneric(msg []byte, oh int) []byte {
	p := GetPaddingLen(msg, oh+PADLEN)
	pad := GeneratePadding(p)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, int64(p))
	s := buf.Bytes()
	s = append(s, msg...)
	s = append(s, pad...)

	return s

}

//removes the padding from a message.
func UnPadGeneric(msg []byte) []byte {
	var p uint64
	p = binary.BigEndian.Uint64(msg[0:8])
	return msg[8 : uint64(len(msg))-p]
}
