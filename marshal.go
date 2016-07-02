package vpki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MarshaledPair is a simple explicitly-named pair of byte slices returned by
// the MarshaledPair function.
type MarshaledPair struct {
	Private, Public []byte
}

// MarshaledPair returns a struct containing the Private and Public marshaled
// keys, useful for writing to disk or usage in a context where PEM-formatted
// certificates will be used.
func (c *Client) MarshaledPair(cn string) (*MarshaledPair, error) {
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

	pubbs := []byte{}

	for _, pub := range crt.Certificate {
		pubbs = append(pubbs, pub...)
		pubbs = append(pubbs, '\n')
	}

	return &MarshaledPair{Private: pkbs, Public: pubbs}, nil
}
