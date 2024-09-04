package wycheproof

type TestV1 struct {
	Algorithm        string   `json:"algorithm"`
	Schema           string   `json:"schema"`
	GeneratorVersion string   `json:"generatorVersion"`
	NumberOfTest     int      `json:"numberOfTests"`
	Header           []string `json:"header"`

	Notes      NotesV1       `json:"notes"`
	TestGroups []TestGroupV1 `json:"testGroups"`
}

type ResultV1 struct {
	BugType     string
	Description string
	Effect      string
}

type NotesV1 struct {
	CompressedSig   `json:"CompressedSignature"`
	InvalidEncoding `json:"InvalidEncoding"`
	InvalidKtv      `json:"InvalidKtv"`
	InvalidSig      `json:"InvalidSignature"`
	Ktv             `json:"Ktv"`
	SigMalleability `json:"SignatureMalleability"`
	TinkOverflow    `json:"TinkOverflow"`
	TruncatedSig    `json:"TruncatedSignature"`
	Valid           `json:"Valid"`
}

type CompressedSig struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
	Effect      string `json:"effect"`
}

type InvalidEncoding struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
	Effect      string `json:"effect"`
}

type InvalidKtv struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type InvalidSig struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
	Effect      string `json:"effect"`
}

type Ktv struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type SigMalleability struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type SigWithGarbage struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type TinkOverflow struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type TruncatedSig struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
	Effect      string `json:"effect"`
}

type Valid struct {
	BugType     string `json:"bugType"`
	Description string `json:"description"`
}

type TestGroupV1 struct {
	Type  string         `json:"type"`
	Pk    PublicKeyV1    `json:"publicKey"`
	PkDer string         `json:"publicKeyDer"`
	PkPem string         `json:"publicKeyPem"`
	PkJwk PublicKeyJwkV1 `json:"publicKeyJwk"`

	Tests []Test `json:"tests"`
}

type PublicKeyV1 struct {
	Type    string `json:"type"`
	Curve   string `json:"curve"`
	KeySize int    `json:"keySize"`
	PK      string `json:"pk"`
}

type PublicKeyJwkV1 struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type Test struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}
