[![Build Status](https://travis-ci.org/andrewstuart/vtls.svg?branch=master)](https://travis-ci.org/andrewstuart/vtls)

# vtls
--
    import "github.com/andrewstuart/vtls"

Package vtls provides a layer of abstraction between the golang stdlib crypto
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
	Certify(string, time.Duration, int) (tls.Certificate, error)
}
```

Certifier abstracts any object that can provide signed certificates (hopefully
valid). The default is expected to be a vtls.Client

#### type Client

```go
type Client struct {
	Mount, Role, Addr, Email string
}
```

Client is the abstraction for a vault client, with convenience methods for
obtaining golang tls.Certificates with minimum risk of key disclosure (keys are
generated locally then CSRs sent to Vault).

#### func (*Client) Certify

```go
func (c *Client) Certify(cn string, ttl time.Duration, strength int) (tls.Certificate, error)
```
Certify takes a server CommonName, ttl, and strength, and returns a
tls.Certificate with a pre-parsed Leaf, or an error

#### func (*Client) SetToken

```go
func (c *Client) SetToken(t string)
```
SetToken sets the Vault token for the Client.

#### func (*Client) SignCSR

```go
func (c *Client) SignCSR(csr *x509.CertificateRequest, ttl time.Duration, strength int) (tls.Certificate, error)
```
SignCSR takes an CertificateRequest template and ttl, and returns a
tls.Certificate with a pre-parsed leaf, or an error

#### type VaultError

```go
type VaultError struct {
	Client Client
	Orig   error
}
```


#### func (*VaultError) Error

```go
func (ve *VaultError) Error() string
```
