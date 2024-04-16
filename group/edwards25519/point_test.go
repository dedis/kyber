package edwards25519

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	inputsTestVectRFC9380 = []string{
		"",
		"abc",
		"abcdef0123456789",
		"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqq",
		"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
)

func TestPoint_Marshal(t *testing.T) {
	p := point{}
	require.Equal(t, "ed.point", fmt.Sprintf("%s", p.MarshalID()))
}

// TestPoint_HasSmallOrder ensures weakKeys are considered to have
// a small order
func TestPoint_HasSmallOrder(t *testing.T) {
	for _, key := range weakKeys {
		p := point{}
		err := p.UnmarshalBinary(key)
		require.Nil(t, err)
		require.True(t, p.HasSmallOrder(), fmt.Sprintf("%s should be considered to have a small order", hex.EncodeToString(key)))
	}
}

// Test_PointIsCanonical ensures that elements >= p are considered
// non canonical
func Test_PointIsCanonical(t *testing.T) {

	// buffer stores the candidate points (in little endian) that we'll test
	// against, starting with `prime`
	buffer := prime.Bytes()
	for i, j := 0, len(buffer)-1; i < j; i, j = i+1, j-1 {
		buffer[i], buffer[j] = buffer[j], buffer[i]
	}

	// Iterate over the 19*2 finite field elements
	point := point{}
	actualNonCanonicalCount := 0
	expectedNonCanonicalCount := 24
	for i := 0; i < 19; i++ {
		buffer[0] = byte(237 + i)
		buffer[31] = byte(127)

		// Check if it's a valid point on the curve that's
		// not canonical
		err := point.UnmarshalBinary(buffer)
		if err == nil && !point.IsCanonical(buffer) {
			actualNonCanonicalCount++
		}

		// flip bit
		buffer[31] |= 128

		// Check if it's a valid point on the curve that's
		// not canonical
		err = point.UnmarshalBinary(buffer)
		if err == nil && !point.IsCanonical(buffer) {
			actualNonCanonicalCount++
		}
	}
	require.Equal(t, expectedNonCanonicalCount, actualNonCanonicalCount, "Incorrect number of non canonical points detected")
}

// Test vectors from: https://datatracker.ietf.org/doc/rfc9380
func Test_ExpandMessageXMDSHA256(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHA256-128"
	outputLength := []int{32, 128}

	expectedHex32byte := []string{
		"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
		"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
		"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
		"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
		"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
	}

	expectedHex128byte := []string{
		"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
		"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
		"ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
		"80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
		"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487",
	}

	h := sha256.New()

	// Short
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXMD(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[0])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex32byte[i], resHex)
	}

	// Long
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXMD(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[1])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex128byte[i], resHex)
	}
}

// Test vectors from: https://datatracker.ietf.org/doc/rfc9380
func Test_ExpandMessageXMDSHA512(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHA512-256"
	h := sha512.New()

	outputLength := []int{32, 128}

	expectedHex32byte := []string{
		"6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba",
		"0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc",
		"087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58",
		"7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3",
		"57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4",
	}

	expectedHex128byte := []string{
		"41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961",
		"7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1",
		"3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac",
		"b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed",
		"05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b",
	}

	// Short
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXMD(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[0])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex32byte[i], resHex)
	}

	// Long
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXMD(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[1])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex128byte[i], resHex)
	}
}

func Test_HashToField(t *testing.T) {
	dst := "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"
	u := hashToField([]byte(inputsTestVectRFC9380[0]), dst, 2)

	var u0, u1 fieldElement
	u0B, _ := big.NewInt(0).SetString("005fe8a7b8fef0a16c105e6cadf5a6740b3365e18692a9c05bfbb4d97f645a6a", 16)
	u1B, _ := big.NewInt(0).SetString("1347edbec6a2b5d8c02e058819819bee177077c9d10a4ce165aab0fd0252261a", 16)

	feFromBytes(&u0, u0B.Bytes())
	feFromBytes(&u1, u1B.Bytes())

	assert.Equal(t, u[0], u0)
	assert.Equal(t, u[1], u1)
}

func Test_HashToPoint(t *testing.T) {
	dst := "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"
	p := new(point)
	p.Hash([]byte(inputsTestVectRFC9380[0]), dst)
	fmt.Printf(p.ge.String())

	var zInv fieldElement
	feInvert(&zInv, &p.ge.Z)

	var x, y fieldElement
	feMul(&x, &p.ge.X, &zInv)
	feMul(&y, &p.ge.Y, &zInv)

	resBig, _ := big.NewInt(0).SetString("2de3780abb67e861289f5749d16d3e217ffa722192d16bbd9d1bfb9d112b98c0", 16)
	var res fieldElement
	feFromBytes(&res, resBig.Bytes())

	assert.Equal(t, x, res)
}
