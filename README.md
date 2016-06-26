# vtls
--
    import "github.com/andrewstuart/vtls"


## Usage

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
	Certify(cn string, ttl time.Duration) (tls.Certificate, error)
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
func (c *Client) Certify(cn string, ttl time.Duration) (tls.Certificate, error)
```
Certify takes a server CommonName and ttl, and returns a tls.Certificate with a
pre-parsed Leaf, or an error

#### func (*Client) SetToken

```go
func (c *Client) SetToken(t string)
```
SetToken sets the Vault token for the Client.

#### func (*Client) SignCSR

```go
func (c *Client) SignCSR(csr *x509.CertificateRequest, ttl time.Duration) (tls.Certificate, error)
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
