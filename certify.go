package vpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"
)

const (
	csrName = "CERTIFICATE REQUEST"
)

type ValidationError struct {
	Domain   string
	Original error
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("Error acquiring cert for %s: %s", ve.Domain, ve.Original)
}

// Certifier abstracts any object that can provide signed certificates
// (hopefully valid for their use case). Concrete implementations ought to
// provide their own ways to configure TTL, key strength, etc. The default
// provided implementation is vpki.Client.
type Certifier interface {
	Cert(cn string) (*tls.Certificate, error)
}

// Certify takes a server CommonName and retruns a tls.Certificate with a
// pre-parsed Leaf, or an error. The strength and ttl for the CSR are
// determined by the Client fields of the same names.
func (c *Client) Cert(cn string) (*tls.Certificate, error) {
	k, err := rsa.GenerateKey(rand.Reader, c.Strength)
	if err != nil {
		return nil, err
	}

	csr := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		EmailAddresses: []string{c.Email},
	}

	return c.SignCSR(csr, k, c.TTL)
}

// SignCSR takes an CertificateRequest template and ttl, and returns a
// tls.Certificate with a pre-parsed leaf, or an error.
func (c *Client) SignCSR(csr *x509.CertificateRequest, k *rsa.PrivateKey, ttl time.Duration) (*tls.Certificate, error) {
	csrBs, err := x509.CreateCertificateRequest(rand.Reader, csr, k)
	if err != nil {
		return nil, err
	}

	pemB := &pem.Block{
		Type:  csrName,
		Bytes: csrBs,
	}

	data := map[string]interface{}{
		"csr":         string(pem.EncodeToMemory(pemB)),
		"common_name": csr.Subject.CommonName,
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

	pubBs := []byte(secret.Data["certificate"].(string))

	pb := &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(k),
		Type:  "RSA PRIVATE KEY",
	}

	crt, err := tls.X509KeyPair(pubBs, pem.EncodeToMemory(pb))
	if err != nil {
		return nil, fmt.Errorf("x509 keypair error: %v", err)
	}

	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &crt, nil
}
