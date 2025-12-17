package edwards25519

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v4/compatible"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
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

func TestPointMarshal(t *testing.T) {
	p := point{}
	require.Equal(t, "ed.point", fmt.Sprintf("%s", p.MarshalID()))
}

// TestPoint_HasSmallOrder ensures weakKeys are considered to have
// a small order
func TestPointHasSmallOrder(t *testing.T) {
	for _, key := range weakKeys {
		p := point{}
		err := p.UnmarshalBinary(key)
		require.Nil(t, err)
		require.True(t, p.HasSmallOrder(), fmt.Sprintf("%s should be considered to have a small order", hex.EncodeToString(key)))
	}
}

// Test_PointIsCanonical ensures that elements >= p are considered
// non canonical
func TestPointIsCanonical(t *testing.T) {

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
func TestExpandMessageXMDSHA256ShortDST(t *testing.T) {
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
func TestExpandMessageXMDSHA256LongDST(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	outputLength := []int{32, 128}

	expectedHex32byte := []string{
		"e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3",
		"52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12",
		"35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521",
		"01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc",
		"20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b",
	}

	expectedHex128byte := []string{
		"14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc",
		"1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267",
		"d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a4249206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982",
		"ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32",
		"78b53f2413f3c688f07732c10e5ced29a17c6a16f717179ffbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c41169d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495",
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
func TestExpandMessageXMDSHA512(t *testing.T) {
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

func TestExpandMessageXOFSHAKE128ShortDST(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHAKE128"
	h := sha3.NewShake128()
	outputLength := []int64{32, 128}

	expectedHex32byte := []string{
		"86518c9cd86581486e9485aa74ab35ba150d1c75c88e26b7043e44e2acd735a2",
		"8696af52a4d862417c0763556073f47bc9b9ba43c99b505305cb1ec04a9ab468",
		"912c58deac4821c3509dbefa094df54b34b8f5d01a191d1d3108a2c89077acca",
		"1adbcc448aef2a0cebc71dac9f756b22e51839d348e031e63b33ebb50faeaf3f",
		"df3447cc5f3e9a77da10f819218ddf31342c310778e0e4ef72bbaecee786a4fe",
	}

	expectedHex128byte := []string{
		"7314ff1a155a2fb99a0171dc71b89ab6e3b2b7d59e38e64419b8b6294d03ffee42491f11370261f436220ef787f8f76f5b26bdcd850071920ce023f3ac46847744f4612b8714db8f5db83205b2e625d95afd7d7b4d3094d3bdde815f52850bb41ead9822e08f22cf41d615a303b0d9dde73263c049a7b9898208003a739a2e57",
		"c952f0c8e529ca8824acc6a4cab0e782fc3648c563ddb00da7399f2ae35654f4860ec671db2356ba7baa55a34a9d7f79197b60ddae6e64768a37d699a78323496db3878c8d64d909d0f8a7de4927dcab0d3dbbc26cb20a49eceb0530b431cdf47bc8c0fa3e0d88f53b318b6739fbed7d7634974f1b5c386d6230c76260d5337a",
		"19b65ee7afec6ac06a144f2d6134f08eeec185f1a890fe34e68f0e377b7d0312883c048d9b8a1d6ecc3b541cb4987c26f45e0c82691ea299b5e6889bbfe589153016d8131717ba26f07c3c14ffbef1f3eff9752e5b6183f43871a78219a75e7000fbac6a7072e2b83c790a3a5aecd9d14be79f9fd4fb180960a3772e08680495",
		"ca1b56861482b16eae0f4a26212112362fcc2d76dcc80c93c4182ed66c5113fe41733ed68be2942a3487394317f3379856f4822a611735e50528a60e7ade8ec8c71670fec6661e2c59a09ed36386513221688b35dc47e3c3111ee8c67ff49579089d661caa29db1ef10eb6eace575bf3dc9806e7c4016bd50f3c0e2a6481ee6d",
		"9d763a5ce58f65c91531b4100c7266d479a5d9777ba761693d052acd37d149e7ac91c796a10b919cd74a591a1e38719fb91b7203e2af31eac3bff7ead2c195af7d88b8bc0a8adf3d1e90ab9bed6ddc2b7f655dd86c730bdeaea884e73741097142c92f0e3fc1811b699ba593c7fbd81da288a29d423df831652e3a01a9374999",
	}

	// Short
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXOF(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[0])
		assert.NoError(t, err)
		assert.Equal(t, expectedHex32byte[i], hex.EncodeToString(res))
	}

	// Long
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXOF(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[1])
		assert.NoError(t, err)
		assert.Equal(t, expectedHex128byte[i], hex.EncodeToString(res))
	}
}

func TestPoint_i2OSP(t *testing.T) {
	// Test a value with a byte size that fits on the output byte length
	value := int64(255) // 0xFF -> fits on 1 byte
	xLen := uint32(1)
	res, err := i2OSP(value, xLen)
	assert.NoError(t, err)
	assert.Equal(t, xLen, uint32(len(res)))

	// Test a value with a byte size that does not fit on the output byte length
	value2 := int64(256)         // 0x100 -> fits on 2 bytes
	assert.NotPanics(t, func() { // Call should not panic but return an error
		_, err = i2OSP(value2, xLen)
		assert.Error(t, err)
	})

	xLen2 := uint32(2)
	res2, err := i2OSP(value2, xLen2)
	assert.NoError(t, err)
	assert.Equal(t, xLen2, uint32(len(res2)))
}

func TestExpandMessageXOFSHAKE128LongDST(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHAKE128-long-DST-111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	h := sha3.NewShake128()
	outputLength := []int64{32, 128}

	expectedHex32byte := []string{
		"827c6216330a122352312bccc0c8d6e7a146c5257a776dbd9ad9d75cd880fc53",
		"690c8d82c7213b4282c6cb41c00e31ea1d3e2005f93ad19bbf6da40f15790c5c",
		"979e3a15064afbbcf99f62cc09fa9c85028afcf3f825eb0711894dcfc2f57057",
		"c5a9220962d9edc212c063f4f65b609755a1ed96e62f9db5d1fd6adb5a8dc52b",
		"f7b96a5901af5d78ce1d071d9c383cac66a1dfadb508300ec6aeaea0d62d5d62",
	}

	expectedHex128byte := []string{
		"3890dbab00a2830be398524b71c2713bbef5f4884ac2e6f070b092effdb19208c7df943dc5dcbaee3094a78c267ef276632ee2c8ea0c05363c94b6348500fae4208345dd3475fe0c834c2beac7fa7bc181692fb728c0a53d809fc8111495222ce0f38468b11becb15b32060218e285c57a60162c2c8bb5b6bded13973cd41819",
		"41b7ffa7a301b5c1441495ebb9774e2a53dbbf4e54b9a1af6a20fd41eafd69ef7b9418599c5545b1ee422f363642b01d4a53449313f68da3e49dddb9cd25b97465170537d45dcbdf92391b5bdff344db4bd06311a05bca7dcd360b6caec849c299133e5c9194f4e15e3e23cfaab4003fab776f6ac0bfae9144c6e2e1c62e7d57",
		"55317e4a21318472cd2290c3082957e1242241d9e0d04f47026f03401643131401071f01aa03038b2783e795bdfa8a3541c194ad5de7cb9c225133e24af6c86e748deb52e560569bd54ef4dac03465111a3a44b0ea490fb36777ff8ea9f1a8a3e8e0de3cf0880b4b2f8dd37d3a85a8b82375aee4fa0e909f9763319b55778e71",
		"19fdd2639f082e31c77717ac9bb032a22ff0958382b2dbb39020cdc78f0da43305414806abf9a561cb2d0067eb2f7bc544482f75623438ed4b4e39dd9e6e2909dd858bd8f1d57cd0fce2d3150d90aa67b4498bdf2df98c0100dd1a173436ba5d0df6be1defb0b2ce55ccd2f4fc05eb7cb2c019c35d5398b85adc676da4238bc7",
		"945373f0b3431a103333ba6a0a34f1efab2702efde41754c4cb1d5216d5b0a92a67458d968562bde7fa6310a83f53dda1383680a276a283438d58ceebfa7ab7ba72499d4a3eddc860595f63c93b1c5e823ea41fc490d938398a26db28f61857698553e93f0574eb8c5017bfed6249491f9976aaa8d23d9485339cc85ca329308",
	}

	// Short
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXOF(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[0])
		assert.NoError(t, err)
		assert.Equal(t, expectedHex32byte[i], hex.EncodeToString(res))
	}

	// Long
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		res, err := expandMessageXOF(h, []byte(inputsTestVectRFC9380[i]), dst, outputLength[1])
		assert.NoError(t, err)
		assert.Equal(t, expectedHex128byte[i], hex.EncodeToString(res))
	}
}

func TestHashToField(t *testing.T) {
	dst := "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"

	// u-value from rfc9380, leading 0 removed
	expectedFieldElem := []string{
		"3fef4813c8cb5f98c6eef88fae174e6e7d5380de2b007799ac7ee712d203f3a",
		"780bdddd137290c8f589dc687795aafae35f6b674668d92bf92ae793e6a60c75",

		"5081955c4141e4e7d02ec0e36becffaa1934df4d7a270f70679c78f9bd57c227",
		"5bdc17a9b378b6272573a31b04361f21c371b256252ae5463119aa0b925b76",

		"285ebaa3be701b79871bcb6e225ecc9b0b32dff2d60424b4c50642636a78d5b3",
		"2e253e6a0ef658fedb8e4bd6a62d1544fd6547922acb3598ec6b369760b81b31",

		"4fedd25431c41f2a606952e2945ef5e3ac905a42cf64b8b4d4a83c533bf321af",
		"2f20716a5801b843987097a8276b6d869295b2e11253751ca72c109d37485a9",

		"6e34e04a5106e9bd59f64aba49601bf09d23b27f7b594e56d5de06df4a4ea33b",
		"1c1c2cb59fc053f44b86c5d5eb8c1954b64976d0302d3729ff66e84068f5fd96",
	}

	j := 0
	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		u := hashToField([]byte(inputsTestVectRFC9380[i]), dst, 2)
		u0Actual := compatible.NewInt(0)
		u1Actual := compatible.NewInt(0)

		feToBn(u0Actual, &u[0])
		feToBn(u1Actual, &u[1])

		assert.Equal(t, expectedFieldElem[j], u0Actual.Text(16))
		assert.Equal(t, expectedFieldElem[j+1], u1Actual.Text(16))
		j += 2
	}
}

func TestHashToPoint(t *testing.T) {
	p := new(point)

	dst := "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"
	expectedPoints := []string{
		"3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6",
		"9a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",

		"608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad",
		"1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",

		"6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472",
		"53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",

		"5fb0b92acedd16f3bcb0ef83f5c7b7a9466b5f1e0d8d217421878ea3686f8524",
		"2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7",

		"efcfde5898a839b00997fbe40d2ebe950bc81181afbd5cd6b9618aa336c1e8c",
		"6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995",
	}

	j := 0
	var x, y, rec fieldElement
	bX := compatible.NewInt(0)
	bY := compatible.NewInt(0)

	for i := 0; i < len(inputsTestVectRFC9380); i++ {
		p.Hash([]byte(inputsTestVectRFC9380[i]), dst)

		feInvert(&rec, &p.ge.Z)
		feMul(&x, &p.ge.X, &rec)
		feToBn(bX, &x)

		feMul(&y, &p.ge.Y, &rec)
		feToBn(bY, &y)

		assert.Equal(t, expectedPoints[j], bX.Text(16))
		assert.Equal(t, expectedPoints[j+1], bY.Text(16))
		j += 2
	}
}
