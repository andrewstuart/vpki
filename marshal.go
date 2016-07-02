package vpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RawPair is a simple explicitly-named pair of byte slices returned by
// the RawPair function.
type RawPair struct {
	Private, Public []byte
}

func (c *Client) RawPair(cn string) (*RawPair, error) {
	crt, err := c.Cert(cn)
	if err != nil {
		return nil, err
	}

	var pkbs []byte

	switch k := crt.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pkbs = x509.MarshalPKCS1PrivateKey(k)
		pkbs = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkbs})
	case *ecdsa.PrivateKey:
		pkbs, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		pkbs = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkbs})
	default:
		return nil, fmt.Errorf("Unsupported private key type")
	}

	crts, err := x509.ParseCertificates(bytes.Join(crt.Certificate, []byte{}))
	if err != nil {
		return nil, fmt.Errorf("Error parsing x509 certs from tls.Certificate{}.Certificate", err)
	}

	pubbs := []byte{}

	for _, crt := range crts {
		bs, err := x509.MarshalPKIXPublicKey(crt.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Error marshling pkix public key", err)
		}

		pubbs = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bs}), pubbs...)
	}

	return &RawPair{Private: pkbs, Public: pubbs}, nil
}
