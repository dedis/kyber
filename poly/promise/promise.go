package promise

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strconv"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/random"
)

var sigMsg []byte = []byte("Promise Signature")
var sigBlameMsg []byte = []byte("Promise Blame Signature")

var protocolName string = "Promise Protocol"

// TODO Pass BlameProof as pointer. Consider generalizing it.
// TODO Add Equal, Marshal, and UnMarshal methods for all
// TODO Add tests for things I haven't yet.
// TODO In tests, only use basicPromise if you ain't going to change it.
// TODO Check the valdidity of PromiseSignature and BlameProof more extensively.
//      make sure same suite, index proper, etc.
// TODO Create valid promise to do basic sanity checking.
// TODO Combine the valid* and Verify*
// TODO Decouple keysuite from sharesuite. Make sure to change marshal when doing so
// TODO It should be i >= p.n
// TODO Add string functions to everything


var uint32Size = binary.Size(uint32(0))

/* The PromiseSignature object is used for insurers to express their approval
 * of a given promise. After receiving a promise and verifying that their share
 * is good, insurers can then produce a signature to send back to the promiser.
 *
 * Upon receiving this, the promiser can then add the signature to its lists of
 * signatures to server as proof that the promiser has gained a sufficient
 * number of insurers.
 */
type PromiseSignature struct {
	
	// The suite used to sign the signature
	suite abstract.Suite
	
	// The signature denoting that the insurer approves of guardining the
	// promise.
	signature []byte
}


/* Initializes a new PromiseSignature
 *
 * Arguments
 *    i   = the index of the Promise share the insurer is approving.
 *    s   = the signing suite
 *    sig = the signature of approval
 *
 * Returns
 *   An initialized PromiseSignature
 */
func (p *PromiseSignature) Init(suite abstract.Suite, sig []byte) *PromiseSignature {
	p.suite     = suite
	p.signature = sig
	return p
}


/* An initialization function for preparing a PromiseSignature for unmarshalling
 *
 * Arguments
 *    s   = the signing suite
 *
 * Returns
 *   An initialized PromiseSignature ready to be unmarshalled
 */
func (p *PromiseSignature) UnmarshalInit(suite abstract.Suite) *PromiseSignature {
	p.suite     = suite
	return p
}

// Tests whether two promise signatures are equal.
func (p *PromiseSignature) Equal(p2 *PromiseSignature) bool {
	return p.suite == p2.suite &&
	       reflect.DeepEqual(p, p2)
}

// Return the encoded length of this polynomial commitment.
func (p *PromiseSignature) MarshalSize() int {
	return uint32Size + len(p.signature)
}

// Encode this polynomial into a byte slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.MarshalSize())
	binary.LittleEndian.PutUint32(buf, uint32(len(p.signature)))
	copy(buf[uint32Size:], p.signature)
	return buf, nil
}

// Decode this polynomial from a slice exactly MarshalSize() bytes long.
func (p *PromiseSignature) UnmarshalBinary(buf []byte) error {
	// The buffer should be at least be able to hold a uint32 and a
	// byte message at least 1 byte long (preferably more)
	if len(buf) < uint32Size + 1 {
		return errors.New("Buffer size too small")
	}

	// Signature length is not needed for unmarshalling proper since all of
	// the remaining buffer will be used for the signature.
	p.signature = buf[uint32Size:]
	return nil
}

func (p *PromiseSignature) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *PromiseSignature) UnmarshalFrom(r io.Reader) (int, error) {
	// Because signatures can be of variable length, MarshalSize will not
	// work until the object has been unmarshalled. However, the size of the
	// signature is provided as a unit32 at the beginning of the message.
	
	// Retrieve the signature length
	buf := make([]byte, uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	
	sigLen := binary.LittleEndian.Uint32(buf)

	// Calculate the length of the entire message and create the new buffer.
	finalBuf := make([]byte, uint32Size + int(sigLen))
	
	// Copy what has already been read into the buffer.
	copy(finalBuf, buf)
	
	// Read the rest and unmarshal.
	m, err2 := io.ReadFull(r, finalBuf[n:])
	if err2 != nil {
		return n+m, err2
	}
	return n+m, p.UnmarshalBinary(finalBuf)
}

// Dump a string representation
func (p *PromiseSignature) String() string {
	s := "{PromiseSignature:\n"
	s += "Suite => " + p.suite.String() + ",\n"
	s += "Signature => " + hex.EncodeToString(p.signature) + "}"
	return s
}

/* PromiseShare is used to represent a secret share of a Promise. When a
 * insurer wants to reveal the secret share it is guarding either to a
 * client or to other insurers to prove that the promiser is crooked, it
 * constructs this object.
 *
 * The key features of a PromiseShare are:
 *	1. The index of the share
 *      2. The share itself
 *      3. The Diffie-Hellman secret between the insurer and promiser
 *
 * #3 is used for verification purposes. Other servers can use it to prove that
 * encrypting #2 with #3 will produce the secret stored in the promise.
 *
 * As mentioned above, PromiseShare's can also be used as "BlameProof" objects.
 *
 * The BlameProof object provides an accountability measure. If a promiser
 * decides to construct a faulty share, insurers can construct a BlameProof
 * to show that the server is malicious. 
 * 
 * The insurer provides the index of the bad secret, the bad secret itself,
 * and its diffie-hellman shared key with the promiser. Other servers can then
 * verify if the promiser is malicious or the insurer is falsely accusing the
 * server.
 *
 * To quickly summarize the blame procedure, two things must hold for the blame
 * to succeed:
 *
 *   1. The provided share when encrypted with the diffie key must equal the
 *   point provided at index bi of the promise. This verifies that the share
 *   was actually intended for the insurer.
 *
 *   2. The provided share must fail to pass pubPoly.Check. This ensures that
 *   the share is actually corrupted and the insurer is not just lying.
 */

type BlameProof struct {

	// The suite all points are from.
	suite abstract.Suite
	
	// The Diffie-Hellman key between the insurer and the promiser.
	diffieKey abstract.Point

	// A HashProve that the insurer properly constructed the Diffie-
	// Hellman key
	diffieKeyProof []byte

	// The signature denoting that the insurer approves of the blame
	signature *PromiseSignature
}

/* Initializes a new BlameProof
 *
 * Arguments
 *    key  = the shared Diffie-Hellman key
 *    dkp  = the proof validating the Diffie-Hellman key
 *    sig  = the insurer's signature
 *
 * Returns
 *   An initialized BlameProof
 */
func (bp *BlameProof) Init(suite abstract.Suite, key abstract.Point, dkp []byte, sig *PromiseSignature) *BlameProof {
	bp.suite          = suite
	bp.diffieKey      = key
	bp.diffieKeyProof = dkp
	bp.signature      = sig
	return bp
}

/* An initialization function for preparing a BlameProof for unmarshalling
 *
 * Arguments
 *    s   = the suite of points in the BlameProof
 *
 * Returns
 *   An initialized BlameProof ready to be unmarshalled
 */
func (bp *BlameProof) UnmarshalInit(suite abstract.Suite) *BlameProof {
	bp.suite     = suite
	return bp
}

// Tests whether two promise signatures are equal.
func (bp *BlameProof) Equal(bp2 *BlameProof) bool {
	return bp.suite == bp2.suite &&
	       bp.diffieKey.Equal(bp2.diffieKey) &&
	       reflect.DeepEqual(bp.diffieKeyProof, bp2.diffieKeyProof) &&
	       bp.signature.Equal(bp2.signature)
}

// Return the encoded length of this polynomial commitment.
func (bp *BlameProof) MarshalSize() int {
	return bp.suite.PointLen() + uint32Size + len(bp.diffieKeyProof) +
	       bp.signature.MarshalSize()
}

// Encode this polynomial into a byte slice exactly MarshalSize() bytes long.
func (bp *BlameProof) MarshalBinary() ([]byte, error) {
	buf := make([]byte, bp.MarshalSize())

	pointLen := bp.suite.PointLen()
	proofLen := len(bp.diffieKeyProof)

	// The buffer is formatted as follows:
	//
	// ||Diffie-Key-Proof-Length||Diffie-Key||Diffie-Key-Proof||Signature||

	binary.LittleEndian.PutUint32(buf, uint32(proofLen))
	
	pointBuf, err := bp.diffieKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	
	copy(buf[uint32Size:], pointBuf)
	copy(buf[uint32Size+pointLen:], bp.diffieKeyProof)
	
	sigBuf, err1 := bp.signature.MarshalBinary()
	if err != nil {
		return nil, err1
	}
	copy(buf[uint32Size+pointLen+proofLen:], sigBuf)

	return buf, nil
}

// Decode this polynomial from a slice exactly MarshalSize() bytes long.
func (bp *BlameProof) UnmarshalBinary(buf []byte) error {

	pointLen   := bp.suite.PointLen()

	// The buffer should be at least be able to hold a uint32, a point,
	// and a byte message at least one byte long. This does not take
	// into account the requirements for a PromiseSignature.
	if len(buf) < uint32Size + pointLen + 1 {
		return errors.New("Buffer size too small")
	}
	
	diffieProofLen := binary.LittleEndian.Uint32(buf)
	bp.diffieKey = bp.suite.Point()
	pointEnd := uint32Size+bp.suite.PointLen()
	if err := bp.diffieKey.UnmarshalBinary(buf[uint32Size:pointEnd]); err != nil {
		panic(err)
		return err
	}
	
	diffieProofStart := uint32Size+pointLen
	diffieProofEnd   := diffieProofStart + int(diffieProofLen)
	bp.diffieKeyProof = make([]byte, diffieProofLen, diffieProofLen)
	copy(bp.diffieKeyProof, buf[diffieProofStart:diffieProofEnd])
	
	bp.signature = new(PromiseSignature).UnmarshalInit(bp.suite)
	
	if err := bp.signature.UnmarshalBinary(buf[diffieProofEnd:]); err != nil {
		return err
	}

	return nil
}

func (bp *BlameProof) MarshalTo(w io.Writer) (int, error) {
	buf, err := bp.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (bp *BlameProof) UnmarshalFrom(r io.Reader) (int, error) {
	// Because signatures and proofs can be of variable length,
	// MarshalSize will not work until the object has been unmarshalled.
	// However, the size of the variable length portions are givin in the
	// buffer making it still possible to decrypt.
	
	// Retrieve the signature length
	buf := make([]byte, uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	
	diffieProofLen := binary.LittleEndian.Uint32(buf)
	pointLen   := bp.suite.PointLen()

	// Calculate the length of the entire message and create the new buffer.
	intermediateBuf := make([]byte, 2*uint32Size + pointLen + int(diffieProofLen))
	
	// Copy what has already been read into the buffer.
	copy(intermediateBuf, buf)
	
	// Read more to determine the length of the signature.
	m, err2 := io.ReadFull(r, intermediateBuf[n:])
	if err2 != nil {
		return n+m, err2
	}
	
	sigLen := binary.LittleEndian.Uint32(intermediateBuf[uint32Size + pointLen + int(diffieProofLen):])
	
	// Calculate the length of the final buffer
	finalBuf := make([]byte, 2*uint32Size + pointLen + int(diffieProofLen) + int(sigLen))

	// Copy what has already been read into the buffer.
	copy(finalBuf, intermediateBuf)


	// Read more to determine the length of the signature.
	o, err3 := io.ReadFull(r, finalBuf[n+m:])
	if err3 != nil {
		return n+m+o, err3
	}
	
	return n+m+o, bp.UnmarshalBinary(finalBuf)
}

func (bp *BlameProof) String() string {
	s := "{BlameProof:\n"
	s += "Suite => " + bp.suite.String() + ",\n"
	s += "Diffie-Hellman Shared Secret => " + bp.diffieKey.String() + ",\n"
	s += "Diffie-Hellman Proof => " + hex.EncodeToString(bp.diffieKeyProof) + ",\n"
	s += "PromiseSignature => " + bp.signature.String() + "}"
	return s
}

/* Promise objects are mechanism by which servers can promise that a certain
 * private key or abstract.Secret can be recomputed by other servers in case
 * the original server goes offline.
 *
 * The Promise struct handles the logic of creating private shares, splitting
 * these shares up for a given number of servers to act as insurers, verifying
 * promises, and providing proof that insurers have indeed taken out approved
 * of backing up the promse.
 *
 * Terms:
 *   promiser = the server making the promise. The own who owns this object.
 *   client = recipients of the promise (aka the clients of the promiser)
 *   insurer = another server who receives a share of the promise and can help
 *              reconstruct it.
 *
 * Development note: The insurers, secrets, and signatures arrays should
 *                   remain synchronized. In other words, the insurers[i],
 *                   secrets[i], and signatures[i] should all refer to the same
 *                   server.
 */
type Promise struct {

	// The cryptographic group to use for the private shares.
	shareSuite abstract.Suite
	
	// The minimum number of shares needed to reconstruct the secret.
	t int
	
	// The minimum number of shares needed before the policy can become
	// active. t <= r <= n
	r int
	
	// The total number of shares to send.
	n int
	
	// The public key of the promiser.
	pubKey abstract.Point
	
	// The public polynomial that is used to verify that a secret share
	// given did indeed come from the appropriate private key.
	pubPoly *poly.PubPoly
	
	// The list of servers who act as insurers of the secret. They will
	// each hold a secret that can be used to decode the promise. The list
	// is identified by the public key of the serers.
	insurers   []abstract.Point
	
	// The list of secret shares to be sent to the insurers. They are
	// encrypted with diffie-hellmen shared secrets between the insurer
	// and the original server.
	secrets    []abstract.Secret
}

func (p *Promise) String() string {
	s := "{Promise:\n"
	s += "Suite => " + p.shareSuite.String() + ",\n"
	s += "t => " + strconv.Itoa(p.t) + ",\n"
	s += "r => " + strconv.Itoa(p.r) + ",\n"
	s += "n => " + strconv.Itoa(p.n) + ",\n"
	s += "Public Key => " + p.pubKey.String() + ",\n"
	s += "Public Polynomial => " + p.pubPoly.String() + ",\n"
	
	insurers := ""
	secrets  := ""
	
	for i := 0; i < p.n; i++ {
		insurers += p.insurers[i].String() + ",\n"
		secrets += p.secrets[i].String() + ",\n"
	}
	s += "Insurers => [" + insurers + "],\n"
	s += "Secrets => [" + secrets + "]}"	
	return s
}

/* To be called by the promiser, initializes a new promise to guard a secret.
 *
 * Arguments
 *    priKey   = the secret to be promised.
 *    t        = the minimum number of shares needed to reconstruct the secret.
 *    r        = the minimum signatures from insurers needed for the promise to
 *               be valid.
 *    insurers = a list of the public keys of servers to act as insurers.
 *
 * Returns
 *   The initialized promise
 *
 * Note
 *   Since shares will be multiplied by Diffie-Hellman keys, they need to be the
 *   same group as the keys.
 */
func (p *Promise) PromiserInit(keyPair *config.KeyPair, t, r int,
	insurers []abstract.Point) *Promise {

	p.t          = t
	p.r          = r
	p.n          = len(insurers)
	p.shareSuite = keyPair.Suite
	p.pubKey     = keyPair.Public
	p.insurers   = insurers
	p.secrets    = make([]abstract.Secret, p.n , p.n )

	// Verify that t <= r <= n
	if p.n  < p.t {
		panic("Not enough insurers for the secret")
	} 
	if p.r < p.t {
		p.r = p.t
	}
	if p.r > p.n {
		p.r = p.n
	}

	// Create the public polynomial and private shares. The total shares made
	// should be equal to teh number of insurers while the minimum shares
	// needed to reconstruct should be t.
	pripoly   := new(poly.PriPoly).Pick(p.shareSuite, p.t, keyPair.Secret, random.Stream)
	prishares := new(poly.PriShares).Split(pripoly, p.n)
	p.pubPoly = new(poly.PubPoly).Commit(pripoly, nil)
	
	// Populate the secrets array. It encrypts each share with a diffie
	// hellman exchange between the originator of the promist and the
	// specific insurer.
	for i := 0 ; i < p.n; i++ {
		diffieBase := p.shareSuite.Point().Mul(insurers[i], keyPair.Secret)
		p.secrets[i] = p.diffieHellmanEncrypt(prishares.Share(i), diffieBase)
	}
	
	return p
}

/* An initialization function for preparing a Promise for unmarshalling
 *
 * Arguments
 *    s   = the suite of points in the Promise
 *
 * Returns
 *   An initialized Promise ready to be unmarshalled
 */
func (p *Promise) UnmarshalInit(suite abstract.Suite) *Promise {
	p.shareSuite     = suite
	return p
}

/* Verifies at a basic level that the Promise was constructed correctly.
 *
 * Arguments
 *    promiserKey = the key the caller believes the Promise to be from
 *
 * Return
 *   an error if the promise is malformed, nil otherwise.
 */
func (p *Promise) VerifyPromise(promiserKey abstract.Point) error {
	// Verify t <= r <= n
	if p.t > p.n || p.t > p.r || p.r > p.n {
		return errors.New("Invalid t-of-n shares promise: expected t <= r <= n")
	}
	if !promiserKey.Equal(p.pubKey) {
		return errors.New("Public key of promise differs from what is expected")
	}
	// There should be a secret and public key for each of the n insurers. 
	if len(p.insurers) != p.n || len(p.secrets) != p.n {
		return errors.New("Insurers and secrets array should be of length promise.n")
	}
	return nil
}

/* Given a Diffie-Hellman shared key, encrypts a secret.
 *
 * Arguments
 *    secret      = the secret to encrypt
 *    diffieBase  = the DH shared key
 *
 * Return
 *   the encrypted secret
 */
func (p *Promise) diffieHellmanEncrypt(secret abstract.Secret, diffieBase abstract.Point) abstract.Secret {	
	buff, err := diffieBase.MarshalBinary()
	if err != nil {
		panic("Bad shared secret for Diffie-Hellman give.")
	}
	cipher := p.shareSuite.Cipher(buff)
	diffieSecret := p.shareSuite.Secret().Pick(cipher)
	return p.shareSuite.Secret().Add(secret, diffieSecret)
}

/* Given a Diffie-Hellman shared key, decrypts a secret.
 *
 * Arguments
 *    secret      = the secret to decrypt
 *    diffieBase  = the DH shared key
 *
 * Return
 *   the decrypted secret
 */
func (p *Promise) diffieHellmanDecrypt(secret abstract.Secret, diffieBase abstract.Point) abstract.Secret {	
	buff, err := diffieBase.MarshalBinary()
	if err != nil {
		panic("Bad shared secret for Diffie-Hellman give.")
	}
	cipher := p.shareSuite.Cipher(buff)
	diffieSecret := p.shareSuite.Secret().Pick(cipher)
	return p.shareSuite.Secret().Sub(secret, diffieSecret)
}


/* Verify that a share has been properly constructed. This should be called by
 * insurers to verify that the share they insure is properly constructed.
 *
 * Arguments
 *    i         = the index of the share to verify
 *    gKeyPair  = the key pair of the insurer of share i
 *
 * Return
 *  an error if the promise is malformed, nil otherwise.
 *
 * Note
 *   Make sure that the proper index and key is specified. Otherwise, the
 *   function will return false because diffieHellmanDecrypt gave the wrong
 *   result. In short, make sure to verify only shares that are allotted to you.
 */
func (p *Promise) VerifyShare(i int, gKeyPair *config.KeyPair) error {
	if i < 0 || i >= p.n {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	msg := "The public key the promise recorded for this" +
	       "shares differs from what is expected"
	if !p.insurers[i].Equal(gKeyPair.Public) {
		return errors.New(msg)
	}
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	if !p.pubPoly.Check(i, share) {
		return errors.New("The share failed the public polynomial check.")
	}
	return nil
}


/* An internal helper function responsible for producing signatures
 *
 * Arguments
 *    i         = the index of the insurer's share
 *    gKeyPair  = the public/private keypair of the insurer.
 *    msg       = the message to sign
 *
 * Return
 *   A PromiseSignature object with the signature.
 */
func (p *Promise) sign(i int, gKeyPair *config.KeyPair, msg []byte) *PromiseSignature {
	set        := anon.Set{gKeyPair.Public}
	sig        := anon.Sign(gKeyPair.Suite, random.Stream, msg,
		set, nil, 0, gKeyPair.Secret)	
	return new(PromiseSignature).Init(gKeyPair.Suite, sig)
}

/* A public wrapper function for sign, Produces a signature for a given insurer
 *
 * Arguments
 *    i         = the index of the insurer's share
 *    gKeyPair  = the public/private keypair of the insurer.
 *
 * Return
 *   A PromiseSignature object with the signature.
 *
 *
 *   It is assumed that the insurer has called VerifyShare first and hence
 *   it is assumed that the input to the function is trusted.
 */
func (p *Promise) Sign(i int, gKeyPair *config.KeyPair) *PromiseSignature {	
	return p.sign(i, gKeyPair, sigMsg)
}

/* Verifies a signature from a given insurer. This is an internal function that
 * enables signatures with different messages to be signed (useful for producing
 * PromiseSignature's and BlameProofs with different signatures). 
 *
 * Arguments
 *    i   = the index of the insurer in the insurers list
 *    sig = the PromiseSignature object containing the signature
 *    msg = the message that was signed
 *
 * Return
 *   an error if the promise is malformed, nil otherwise.
 */
func (p *Promise) verifySignature(i int, sig *PromiseSignature, msg []byte) error {
	if sig.signature == nil {
		return errors.New("Nil signature")
	}
	if i < 0 || i >= p.n {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	set := anon.Set{p.insurers[i]}
	_, err := anon.Verify(sig.suite, msg, set, nil, sig.signature)
	return err
}

/* Verifies a signature from a given insurer
 *
 * Arguments
 *    i   = the index of the insurer in the insurers list
 *    sig = the PromiseSignature object containing the signature
 *
 * Return
 *   an error if the promise is malformed, nil otherwise.
 */
func (p *Promise) VerifySignature(i int, sig *PromiseSignature) error {
	return p.verifySignature(i, sig, sigMsg)
}

/* Reveals the secret share that the insurer has been protecting. The insurer
 * decodes the secret and provides the Diffie-Hellman secret between it and
 * the promiser so that anyone receiving the secret share can confirm that it
 * is valid.
 *
 * Arguments
 *    i        = the index of the insurer
 *    gkeyPair = the keypair of the insurer
 *
 * Return
 *   the revealed private share
 */
func (p *Promise) RevealShare(i int, gKeyPair *config.KeyPair) abstract.Secret {
	diffieBase := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	share      := p.diffieHellmanDecrypt(p.secrets[i], diffieBase)
	return share
}

/* Verify that a revealed share is properly formed. This should be calle by
 * clients or others who request an insurer to reveal its secret.
 *
 * Arguments
 *    i     = the index of the share
 *    share = the share to validate.
 *
 * Return
 *   Whether the secret is valid
 */
func (p *Promise) VerifyRevealedShare(i int, share abstract.Secret) error {
	if i > p.n || i < 0 {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	if !p.pubPoly.Check(i, share) {
		return errors.New("The share failed the public polynomial check.")
	}
	return nil
}

/* Create a proof that the promiser maliciously constructed a given secret.
 *
 * Arguments
 *    i         = the index of the malicious secret
 *    gKeyPair  = the key pair of the insurer of share i
 *
 * Return
 *   A proof object that the promiser is malicious or nil if an error occurs
 *   An error object denoting the status of the proof construction
 */
func (p *Promise) Blame(i int, gKeyPair *config.KeyPair) (*BlameProof, error) {

	diffieKey  := p.shareSuite.Point().Mul(p.pubKey, gKeyPair.Secret)
	insurerSig := p.sign(i, gKeyPair, sigBlameMsg)

	choice := make(map[proof.Predicate]int)
	pred := proof.Rep("D", "x", "P")
	choice[pred] = 1

	rand := p.shareSuite.Cipher(abstract.RandomKey)

	sval := map[string]abstract.Secret{"x": gKeyPair.Secret}
	pval := map[string]abstract.Point{"D": diffieKey, "P": p.pubKey}
	prover := pred.Prover(p.shareSuite, sval, pval, choice)
	proof, err := proof.HashProve(p.shareSuite, protocolName, rand, prover)
	if err != nil {
		return nil, err
	}	
	return new(BlameProof).Init(p.shareSuite, diffieKey, proof, insurerSig), nil
}


/* Verify that a blame proof is jusfitied.
 *
 * Arguments
 *    i     = the index of the share subject to blame
 *    proof = proof that alleges that a promiser constructed a bad share.
 *
 * Return
 *   an error if the blame is unjustified or nil if the blame is justified.
 */
func (p *Promise) VerifyBlame(i int, blSig *BlameProof) error {

	if i < 0 || i >= p.n {
		return errors.New("Invalid index. Expected 0 <= i < n")
	}
	if err := p.verifySignature(i, blSig.signature, sigBlameMsg); err != nil {
		return err
	}

	pval     := map[string]abstract.Point{"D": blSig.diffieKey, "P": p.pubKey}
	pred     := proof.Rep("D", "x", "P")
	verifier := pred.Verifier(p.shareSuite, pval)
	if err := proof.HashVerify(p.shareSuite, protocolName, verifier, blSig.diffieKeyProof); err != nil {
		return err
	}

	share := p.diffieHellmanDecrypt(p.secrets[i], blSig.diffieKey)
	if p.pubPoly.Check(i, share) {
		return errors.New("Unjustified blame. The share checks out okay.")
	}
	return nil
}

// Tests whether two promises are equal.
func (p *Promise) Equal(p2 *Promise) bool {
	if p.n != p2.n {
		return false
	}
	for i := 0 ; i < p.n; i++ {
		if !p.secrets[i].Equal(p2.secrets[i]) ||
		   !p.insurers[i].Equal(p2.insurers[i]) {
		 	return false  
		}
	}
	return p.shareSuite == p2.shareSuite && p.t == p2.t && p.r == p2.r &&
	       p.n == p2.n && p.pubKey.Equal(p2.pubKey) &&
	       p.pubPoly.Equal(p2.pubPoly)
}

// Return the encoded length of this polynomial commitment.
func (p *Promise) MarshalSize() int {
	return 3*uint32Size + p.shareSuite.PointLen() + p.pubPoly.MarshalSize()+
	       p.n*p.shareSuite.PointLen() + p.n*p.shareSuite.SecretLen()
}

// Encode this polynomial into a byte slice exactly MarshalSize() bytes long.
func (p *Promise) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.MarshalSize())

	pointLen  := p.shareSuite.PointLen()
	polyLen   := p.pubPoly.MarshalSize()
	secretLen := p.shareSuite.SecretLen()

	// The buffer is formatted as follows:
	//
	// ||n||t||r||pubKey||pubPoly||==insurers_array==||==secrets==||
	//
	// Remember: n == len(insurers) == len(secrets)

	// Encode n, r, t
	binary.LittleEndian.PutUint32(buf, uint32(p.n))
	binary.LittleEndian.PutUint32(buf[uint32Size:], uint32(p.t))
	binary.LittleEndian.PutUint32(buf[2*uint32Size:], uint32(p.r))


	// Encode pubKey and pubPoly
	pointBuf, err := p.pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}	
	copy(buf[3*uint32Size:], pointBuf)

	polyBuf, err := p.pubPoly.MarshalBinary()
	if err != nil {
		return nil, err
	}	
	copy(buf[3*uint32Size+pointLen:], polyBuf)	
	
	
	// Encode the insurers and secrets array
	bufPos := 3*uint32Size+pointLen+polyLen
	
	// Based on sharing.go code
	for i := range p.insurers {
		pb, err := p.insurers[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(buf[bufPos + i*pointLen:], pb)
	}
	bufPos += p.n*pointLen

	for i := range p.secrets {
		pb, err := p.secrets[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(buf[bufPos + i*secretLen:], pb)
	}
	return buf, nil
}

// Decode this polynomial from a slice exactly MarshalSize() bytes long.
func (p *Promise) UnmarshalBinary(buf []byte) error {

	pointLen  := p.shareSuite.PointLen()
	secretLen := p.shareSuite.SecretLen()

	// Decode n, r, t
	p.n = int(binary.LittleEndian.Uint32(buf))
	p.t = int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	p.r = int(binary.LittleEndian.Uint32(buf[2*uint32Size:]))

	bufPos := 3*uint32Size
	
	// Decode pubKey and pubPoly
	p.pubKey = p.shareSuite.Point()
	if err := p.pubKey.UnmarshalBinary(buf[bufPos:bufPos+pointLen]); err != nil {
		return err
	}
	bufPos += pointLen
	
	
	p.pubPoly =  new(poly.PubPoly)
	p.pubPoly.Init(p.shareSuite, p.t, nil)
	polyLen   := p.pubPoly.MarshalSize()
	if err := p.pubPoly.UnmarshalBinary(buf[bufPos:bufPos+polyLen]); err != nil {
		return err
	}
	bufPos += polyLen
	
	
	p.insurers = make([]abstract.Point, p.n, p.n)
	// Encode the insurers and secrets array
	// Based on sharing.go code
	for i := 0; i < p.n; i++ {
		p.insurers[i] = p.shareSuite.Point()
		start := bufPos + i*pointLen
		end   := start + pointLen
		if err := p.insurers[i].UnmarshalBinary(buf[start:end]); err != nil {
			return err
		}
	}
	bufPos += p.n*pointLen
	p.secrets = make([]abstract.Secret, p.n, p.n)
	for i := 0; i < p.n; i++ {
		p.secrets[i] = p.shareSuite.Secret()
		start := bufPos + i*secretLen
		end   := start + secretLen
		if err := p.secrets[i].UnmarshalBinary(buf[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Promise) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (p *Promise) UnmarshalFrom(r io.Reader) (int, error) {
	// Promise objects are easier to marshal than others in this file since
	// them are fixed-length. Since p.n (the size of all arrays) is stored
	// at the beginning along with p.t (needed to reconstruct the pubPoly),
	// the code can rely on MarshalSize.
	
	// Retrieve p.n and p.t
	buf := make([]byte, 2*uint32Size)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}

	p.n = int(binary.LittleEndian.Uint32(buf))
	p.t = int(binary.LittleEndian.Uint32(buf[uint32Size:]))
	p.pubPoly = new(poly.PubPoly)
	p.pubPoly.Init(p.shareSuite, p.t, nil)
	
	
	// Calculate the length of the final buffer
	finalBuf := make([]byte, p.MarshalSize())

	// Copy what has already been read into the buffer.
	copy(finalBuf, buf)


	// Read more to determine the length of the signature.
	m, err2 := io.ReadFull(r, finalBuf[n:])
	if err2 != nil {
		return n+m, err2
	}
	
	return n+m, p.UnmarshalBinary(finalBuf)
}



/* The PromiseState object is responsible for maintaining state for a given
 * Promise object. It will contain three main pieces:
 *
 *    1. The promise itself, which will be an immutable object 
 *    2. Shares of the private secret the server has received so far
 *    3. A list of signatures from insurers cerifying the promise
 *
 * Each server will contain a PromiseState for each promise to be tracked.
 */
type PromiseState struct {

	// The actual promise
	Promise *Promise
	
	// Primarily for use by clients, this contains shares the client
	// has currently obtained from insurers. This is what will be used to
	// reconstruct the secret.
	PriShares * poly.PriShares
	
	// A list of signatures validating that an insurer has cerified the
	// secret share it is guarding.
	signatures []*PromiseSignature
	
	// A list of blame proofs in which an insurer blames the promise to be
	// malformed
	blames []*BlameProof
}



func (ps *PromiseState) Init(promise *Promise) *PromiseState {

	ps.Promise = promise
	
	// Initialize a new PriShares based on information from the promise
	// object.
	ps.PriShares = new(poly.PriShares)
	ps.PriShares.Empty(promise.shareSuite, promise.t, promise.n)

	// There will be at most n signatures and blame proofs, one per insurer
	ps.signatures = make([]*PromiseSignature, promise.n, promise.n)
	ps.blames    = make([]*BlameProof, promise.n, promise.n)
	return ps
}


/* To add a share to PriShares, do:
 *
 *     p.PriShares.SetShare(index, share)
 *
 * To reconstruct the secred, do:
 *
 *     p.PriShares.Secret()
 *
 * Be warned that Secret will panic unless there are enough
 * shares to reconstruct the secret.
 */


/* Adds a signature from an insurer to the PromiseState
 *
 * Arguments
 *    i   = the index in the signature array this signature belogns
 *    sig = the PromiseSignature to add
 *
 * Postcondition
 *   The signature has been added
 *
 * Note
 *   Be sure to call ps.Promise.VerifySignature before calling this function
 */
func (ps *PromiseState) AddSignature(i int, sig *PromiseSignature) {
	ps.signatures[i] = sig
}

/* Adds a blame proof from an insurer to the PromiseState
 *
 * Arguments
 *    i      = the index in the signature array this BlameProof belongs
 *    bproof = the BlameProof to add
 *
 * Postcondition
 *   The BlameProof has been added
 *
 * Note
 *   Be sure to call ps.Promise.VerifyBlame before calling this function
 */
func (ps *PromiseState) AddBlameProof(i int, bproof *BlameProof) {
	ps.blames[i] = bproof
}

/* Checks whether the Promise object has received enough signatures to be
 * considered certified.
 *
 * Arguments
 *   promiserKey = the public key the server believes the promise to have come
 *                 from
 *
 * Return
 *   whether the Promise is now cerified and considered trustworthy.
 *
 * Technical Notes: The function goes through the list of signatures and checks
 *                  whether the signature is properly signed. If at least r of
 *                  these are signed and r is greater than t (the minimum number
 *                  of shares needed to reconstruct the secret), the promise is
 *                  considered valid.
 */
func (ps *PromiseState) PromiseCertified(promiserKey abstract.Point) error {
	if err := ps.Promise.VerifyPromise(promiserKey); err != nil {
		return err
	}

	validSigs := 0
	for i := 0; i < ps.Promise.n; i++ {
		// Check whether the signature is initialized. Otherwise, bad
		// things will happen.
		if ps.signatures[i] != nil &&
		   ps.Promise.VerifySignature(i, ps.signatures[i]) == nil {
			validSigs += 1
		}
		
		if ps.blames[i] != nil && ps.Promise.VerifyBlame(i, ps.blames[i]) == nil {
			return errors.New("A valid blame proofs proves this Promise to be uncertified.")
		}
	}
	if validSigs < ps.Promise.r {
		return errors.New("Not enough signatures yet to be certified")
	}
	return nil
}

