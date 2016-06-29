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

var emptyCert = tls.Certificate{}

// Certify takes a server CommonName, ttl, and strength, and returns a
// tls.Certificate with a pre-parsed Leaf, or an error
func (c *Client) Certify(cn string, ttl time.Duration, strength int) (tls.Certificate, error) {
	csr := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		EmailAddresses: []string{c.Email},
	}

	return c.SignCSR(csr, ttl, strength)
}

// SignCSR takes an CertificateRequest template and ttl, and returns a
// tls.Certificate with a pre-parsed leaf, or an error
func (c *Client) SignCSR(csr *x509.CertificateRequest, ttl time.Duration, strength int) (tls.Certificate, error) {
	k, err := rsa.GenerateKey(rand.Reader, strength)
	if err != nil {
		return emptyCert, err
	}

	csrBs, err := x509.CreateCertificateRequest(rand.Reader, csr, k)
	if err != nil {
		return emptyCert, err
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
		return emptyCert, err
	}

	pubBs := []byte(secret.Data["certificate"].(string))

	pb := &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(k),
		Type:  "RSA PRIVATE KEY",
	}

	crt, err := tls.X509KeyPair(pubBs, pem.EncodeToMemory(pb))
	if err != nil {
		return emptyCert, fmt.Errorf("x509 keypair error: %v", err)
	}

	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return emptyCert, err
	}

	return crt, nil
}
