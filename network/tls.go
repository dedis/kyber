package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/dedis/kyber/util/random"
)

// certMaker holds the data necessary to make a certificate on the
// fly, cache it, expire it, and give it to crypto/tls via the
// GetCertificate and GetClientCertificate callbacks.
//
// TODO: make the CN be the public key, and include a signature over the CN in the cert proving that we
// hold the private key associated with the public key.

type certMaker struct {
	sync.Mutex
	c       *tls.Certificate
	expires time.Time
	si      *ServerIdentity
	// sig is the Schnorr signature of si.Public, added into the certificate as an extension
	sig    []byte
	suite  Suite
	serial *big.Int
}

func newCertMaker(si *ServerIdentity, s Suite) (*certMaker, error) {
	sig, err := si.SignPublicKey(s)
	if err != nil {
		return nil, fmt.Errorf("could not sign the ServerIdentity's public key: %v", err)
	}

	cm := &certMaker{
		si:     si,
		sig:    sig,
		suite:  s,
		serial: new(big.Int),
	}

	// Choose a random serial number to start with.
	r := random.Bits(128, true, random.New())
	cm.serial.SetBytes(r)

	return cm, nil
}

func (cm *certMaker) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.Lock()
	defer cm.Unlock()

	if cm.expires.Before(time.Now()) {
		err := cm.makeCert()
		if err != nil {
			return nil, err
		}
	}

	return cm.c, nil
}

// TODO: Get an enterprise object ID for DEDIS.
var asnPubkeySig = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2499, 1, 1}

func (cm *certMaker) makeCert() error {
	one := new(big.Int).SetUint64(1)
	cm.serial.Add(cm.serial, one)

	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotAfter:              time.Now().Add(2 * 24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * 24 * time.Hour),
		SerialNumber:          cm.serial,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		Subject:               pkix.Name{CommonName: cm.si.private.String()},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asnPubkeySig,
				Critical: false,
				Value:    cm.sig,
			},
		},
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	cDer, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return err
	}
	certs, err := x509.ParseCertificates(cDer)
	if err != nil {
		return err
	}
	if len(certs) < 1 {
		return errors.New("no certificate found")
	}

	cm.c = &tls.Certificate{
		PrivateKey:  k,
		Certificate: [][]byte{cDer},
		Leaf:        certs[0],
	}
	// To be safe, we expire our cache of this cert one hour
	// before clients will refuse it.
	cm.expires = tmpl.NotAfter.Add(-1 * time.Hour)

	return nil
}

// NewTLSListener makes a new TCPListner that is configured for TLS.
// TODO: Why can't we just use NewTCPListener like usual, but detect
// the ConnType from the ServerIdentity?
func NewTLSListener(si *ServerIdentity, s Suite) (*TCPListener, error) {
	tcp, err := NewTCPListener(si.Address, s)
	if err != nil {
		return nil, err
	}

	ch, err := newCertMaker(si, s)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		GetCertificate: ch.getCertificate,
	}
	tcp.listener = tls.NewListener(tcp.listener, tlsCfg)
	return tcp, nil
}

// NewTLSAddress returns a new Address that has type TLS with the given
// address addr.
func NewTLSAddress(addr string) Address {
	return NewAddress(TLS, addr)
}

func tlsConfig(si *ServerIdentity) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

// NewTLSConn will open a TCPConn to the given server over TLS.
// It will (eventually) check that the remote server has proven
// it holds the given Public key by self-signing a certificate
// linked to that key.
func NewTLSConn(si *ServerIdentity, suite Suite) (conn *TCPConn, err error) {
	if si.Address.ConnType() != TLS {
		return nil, errors.New("not a tls server")
	}
	netAddr := si.Address.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		var c net.Conn
		c, err = tls.Dial("tcp", netAddr, tlsConfig(si))
		if err == nil {
			conn = &TCPConn{
				endpoint: si.Address,
				conn:     c,
				suite:    suite,
			}
			return
		}
		if i < MaxRetryConnect {
			time.Sleep(WaitRetry)
		}
	}
	if err == nil {
		err = ErrTimeout
	}
	return
}
