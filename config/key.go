package config

import (
	"crypto/cipher"
	"errors"
	"log"
	"os"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/base64"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/util"
)

// KeyPair represents a public/private keypair
// together with the ciphersuite the key was generated from.
type KeyPair struct {
	Suite  abstract.Suite  // Ciphersuite this keypair is for
	Public abstract.Point  // Public key
	Secret abstract.Scalar // Secret key
}

// NewKeyPair directly creates a secret/public key pair
func NewKeyPair(suite abstract.Suite) *KeyPair {
	kp := new(KeyPair)
	kp.Gen(suite, random.Stream)
	return kp
}

// Generate a fresh public/private keypair with the given ciphersuite,
// using a given source of cryptographic randomness.
func (p *KeyPair) Gen(suite abstract.Suite, random cipher.Stream) {
	p.Suite = suite
	p.Secret = suite.Scalar().Pick(random)
	p.Public = suite.Point().Mul(nil, p.Secret)
}

// PubId returns the base64-encoded HashId for this KeyPair's public key.
func (p *KeyPair) PubId() string {
	buf, _ := p.Public.MarshalBinary()
	hash := abstract.Sum(p.Suite, buf)
	return base64.RawURLEncoding.EncodeToString(hash)
}

// Keys represents a set of public/private keypairs
// an application is configured to use to identify itself.
// The caller should embed an instance of Keys
// in its application-specific configData struct.
type Keys []KeyInfo

// KeyInfo represents configuration data for a particular public key,
// consisting of the name of the ciphersuite the public key was generated from
// and the unpadded, base64-encoded Hash-Id of the public key itself
// using the appropriate ciphersuite's hash function.
// The corresponding private key is stored separately for security.
type KeyInfo struct {
	Suite string // Name of this key's ciphersuite
	PubId string // Public key's base64-encoded hash-ID
}

// Retrieve a set of public/private keypairs configured for this application.
// The caller must provide a pointer to an instance of the Keys struct,
// which should be embedded in the configData object that was passed to Load.
// If the provided defaultSuite is non-nil and no keypairs are configured yet,
// automatically creates and saves a keypair with the specified defaultSuite.
//
// If any of the configured public keys cannot be loaded for whatever reason,
// such as a key's ciphersuite becoming no-longer-supported for example,
// logs a warning but continues to load any other configured keys.
//
func (f *File) Keys(keys *Keys, suites map[string]abstract.Suite,
	defaultSuite abstract.Suite) ([]KeyPair, error) {

	// Read all existing configured keys
	klist := *keys
	pairs := make([]KeyPair, 0, len(klist))
	for i := range klist {
		pair, err := f.Key(&klist[i], suites)
		if err != nil {
			log.Printf("Cannot load public key '%v': %v",
				klist[i].PubId, err.Error())
			continue
		}
		pairs = append(pairs, pair)
	}

	// Create a keypair if none exists yet and we have a defaultSuite.
	if len(pairs) == 0 && defaultSuite != nil {
		pair, err := f.GenKey(keys, defaultSuite)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}

	return pairs, nil
}

// Retrieve a public/private keypair for a given KeyInfo configuration record.
func (f *File) Key(key *KeyInfo, suites map[string]abstract.Suite) (KeyPair, error) {

	// XXX support passphrase-encrypted or system-keychain keys

	// Lookup the appropriate ciphersuite for this public key.
	suite := suites[key.Suite]
	if suite == nil {
		return KeyPair{},
			errors.New("Unsupported ciphersuite '" + key.Suite + "'")
	}

	// Read the private key file
	secname := f.dirName + "/sec-" + key.PubId
	secf, err := os.Open(secname)
	if err != nil {
		return KeyPair{}, err
	}
	defer secf.Close()

	p := KeyPair{}
	p.Suite = suite
	if err := suite.Read(secf, &p.Secret); err != nil {
		return KeyPair{}, err
	}

	// Reconstruct and verify the public key
	p.Public = suite.Point().Mul(nil, p.Secret)
	if p.PubId() != key.PubId {
		return KeyPair{},
			errors.New("Secret does not yield public key " +
				key.PubId)
	}

	return p, nil
}

// Generate a new public/private keypair with the given ciphersuite
// and Save it to the application's previously-loaded configuration.
func (f *File) GenKey(keys *Keys, suite abstract.Suite) (KeyPair, error) {

	// Create the map if it doesn't exist
	//	if *keys == nil {
	//		*keys = make(map[string] KeyInfo)
	//	}

	// Create a fresh public/private keypair
	p := KeyPair{}
	p.Gen(suite, random.Stream)
	pubId := p.PubId()

	// Write the private key file
	secname := f.dirName + "/sec-" + pubId
	r := util.Replacer{}
	if err := r.Open(secname); err != nil {
		return KeyPair{}, err
	}
	defer r.Abort()

	// Write the secret key
	if err := suite.Write(r.File, &p.Secret); err != nil {
		return KeyPair{}, err
	}

	// Commit the secret key
	if err := r.Commit(); err != nil {
		return KeyPair{}, err
	}

	// Re-write the config file with the new public key
	*keys = append(*keys, KeyInfo{suite.String(), pubId})
	if err := f.Save(); err != nil {
		return KeyPair{}, err
	}

	return p, nil
}
