package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"
)

// certHolder holds the data necessary to make certificates on the fly and give them to crypto/tls
// via the GetCertificate and GetClientCertificate callbacks.
//
// TODO: actually do it on the fly, add a cache, expire the cache before the cert expires
// TODO: make the CN be the public key, and include a signature over the CN in the cert proving that we
// hold the private key associated with the public key.

type certHolder struct {
	c *tls.Certificate
}

func (ch *certHolder) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ch.c, nil
}

// NewTLSListener makes a new TCPListner that is configured for TLS.
// TODO: Why can't we just use NewTCPListener like usual, but detect
// the ConnType from the ServerIdentity?
func NewTLSListener(sid *ServerIdentity, s Suite) (*TCPListener, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	cn := "test.dedis.ch"
	sn := new(big.Int).SetInt64(99)

	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		IsCA:                  false,
		DNSNames:              []string{cn},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		NotBefore:             time.Now().Add(-1 * 24 * time.Hour),
		SerialNumber:          sn,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Subject:               pkix.Name{CommonName: cn},
	}
	cDer, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(cDer)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		panic("too many certs?")
	}
	ch := &certHolder{c: &tls.Certificate{
		PrivateKey:  k,
		Certificate: [][]byte{cDer},
		Leaf:        certs[0]},
	}

	tcp, err := NewTCPListener(sid.Address, s)
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
