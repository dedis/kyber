package bn254

import "bytes"

func zeroPadBytes(m []byte, outlen int) []byte {
	if len(m) < outlen {
		padlen := outlen - len(m)
		out := bytes.NewBuffer(make([]byte, padlen, outlen))
		out.Write(m)
		return out.Bytes()
	}
	return m
}
