package vpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"
)

// RawPair is a simple explicitly-named pair of byte slices returned by
// the RawPair function.
type RawPair struct {
	Private, Public []byte
}

// RawSignCSR takes a certificate request template, private keye, and ttl, and
// returns the private/public keypair, unparsed, for any applications which may
// need to consume the certificates directly in their PEM form. The RawPair
// struct is used to help prevent transposition errors by explicitly naming the
// public/private pairs rather than returning two byte slices.
func (c *Client) RawSignCSR(csr *x509.CertificateRequest, k *rsa.PrivateKey, ttl time.Duration) (*RawPair, error) {
	csrBs, err := x509.CreateCertificateRequest(rand.Reader, csr, k)
	if err != nil {
		return nil, err
	}

	pubBs, err := c.rawPub(csrBs, csr.Subject.CommonName, ttl)
	if err != nil {
		return nil, err
	}

	return &RawPair{Public: pubBs, Private: pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})}, nil
}

// RawCert is a very high-level method used to obtain the raw certificate data.
func (c *Client) RawCert(cn string) (*RawPair, error) {
	csr, k, err := c.getCSR(cn)
	if err != nil {
		return nil, err
	}
	return c.RawSignCSR(csr, k, c.TTL)
}

func (c *Client) rawPub(csr []byte, cn string, ttl time.Duration) ([]byte, error) {
	pemB := &pem.Block{
		Type:  csrName,
		Bytes: csr,
	}

	data := map[string]interface{}{
		"csr":         string(pem.EncodeToMemory(pemB)),
		"common_name": cn,
		"format":      "pem_bundle",
		"ttl":         ttl.String(),
	}

	if c.sw == nil {
		c.init()
	}

	secret, err := c.sw.Write(c.Mount+"/sign/"+c.Role, data)
	if err != nil {
		return nil, err
	}

	return []byte(secret.Data["certificate"].(string)), nil
}
