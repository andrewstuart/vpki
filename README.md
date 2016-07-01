[![Build Status](https://travis-ci.org/andrewstuart/vpki.svg?branch=master)](https://travis-ci.org/andrewstuart/vpki) [![GoDoc](https://godoc.org/go.astuart.co/vpki?status.svg)](https://godoc.org/go.astuart.co/vpki)

# vpki
--
    import "go.astuart.co/vpki"

Package vpki provides a layer of abstraction between the golang stdlib crypto
primitives and common crypto uses (e.g. serving HTTPS) and the functionality
provided by Vault. Internally, the library generates private keys locally and
sends CSRs to the vault server, so that private keys are never transmitted.

## Usage

```go
var (

	//DefaultTTL is the default TTL the library will request for certificates
	DefaultTTL = day
	//DefaultStrength is the default strength of RSA keys generated
	DefaultStrength = 2048
)
```

#### func  ListenAndServeTLS

```go
func ListenAndServeTLS(addr string, handler http.Handler, crt Certifier) error
```
ListenAndServeTLS mostly mirrors the http.ListenAndServeTLS API, but generates
the certificates for the server automatically via vault, with a short TTL. The
function only needs an additional Certifier parameter which can generate signed
certificates in order to work properly.

#### type Certifier

```go
type Certifier interface {
	Cert(cn string) (*tls.Certificate, error)
}
```

Certifier abstracts any object that can provide signed certificates (hopefully
valid for their use case). Concrete implementations ought to provide their own
ways to configure TTL, key strength, etc. The default provided implementation is
vpki.Client.

#### type Client

```go
type Client struct {
	Mount, Role, Addr, Email string
	Strength                 int
	TTL                      time.Duration
}
```

Client is the abstraction for a vault client, with convenience methods for
obtaining golang tls.Certificates with minimum risk of key disclosure (keys are
generated locally then CSRs sent to Vault).

#### func (*Client) Cert

```go
func (c *Client) Cert(cn string) (*tls.Certificate, error)
```
Certify takes a server CommonName and retruns a tls.Certificate with a
pre-parsed Leaf, or an error. The strength and ttl for the CSR are determined by
the Client fields of the same names.

#### func (*Client) SetToken

```go
func (c *Client) SetToken(t string)
```
SetToken sets the Vault token for the Client.

#### func (*Client) SignCSR

```go
func (c *Client) SignCSR(csr *x509.CertificateRequest, k *rsa.PrivateKey, ttl time.Duration) (*tls.Certificate, error)
```
SignCSR takes an CertificateRequest template and ttl, and returns a
tls.Certificate with a pre-parsed leaf, or an error

#### type SNICertifier

```go
type SNICertifier interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}
```

SNICertifier abstracts the basic GetCertificate method used in TLSOpts, and also
implemented by libraries like rsc.io/letsencrypt

#### type ValidationError

```go
type ValidationError struct {
	Domain   string
	Original error
}
```


#### func (*ValidationError) Error

```go
func (ve *ValidationError) Error() string
```

#### type VaultError

```go
type VaultError struct {
	Client Client
	Orig   error
}
```

VaultError is an error originating from a vault client. Errors coming from the
vpki library should be type checked against this error (use a type switch)

#### func (*VaultError) Error

```go
func (ve *VaultError) Error() string
```
