package vtls

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	day  = 24 * time.Hour
	year = 365 * day

	//DefaultTTL is the default TTL the library will request for certificates
	DefaultTTL = day
)

type certCache struct {
	m   map[string]*tls.Certificate
	mut *sync.RWMutex
	crt Certifier
	ttl time.Duration
}

func newCertCache(crt Certifier) *certCache {
	return &certCache{
		m:   map[string]*tls.Certificate{},
		mut: &sync.RWMutex{},
		crt: crt,
		ttl: DefaultTTL,
	}
}

func (cc *certCache) add(name string) (*tls.Certificate, error) {
	crt, err := cc.crt.Certify(name, cc.ttl)
	if err != nil {
		return nil, err
	}

	cc.mut.Lock()
	cc.m[name] = &crt
	cc.mut.Unlock()
	return &crt, nil
}

func (cc *certCache) get(name string) (*tls.Certificate, error) {
	lkr := cc.mut.RLocker()
	lkr.Lock()

	if c, ok := cc.m[name]; ok {
		n := time.Now()
		if n.After(c.Leaf.NotBefore) && n.Before(c.Leaf.NotAfter) {
			lkr.Unlock()
			return c, nil
		}
	}
	lkr.Unlock()

	return cc.add(name)
}

// ListenAndServeTLS mostly mirrors the http.ListenAndServeTLS API, but
// generates the certificates for the server automatically via vault, with a
// short TTL. The function only needs an additional Certifier parameter which
// can generate signed certificates in order to work properly.
func ListenAndServeTLS(addr string, handler http.Handler, crt Certifier) error {
	certs := newCertCache(crt)

	tl, err := tls.Listen("tcp", addr, &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName == "" {
				return nil, fmt.Errorf("Cannot generate certs without TLS SNI (no server name was indicated)")
			}
			return certs.get(h.ServerName)
		},
	})

	if err != nil {
		return err
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}

	return http.Serve(tl, handler)
}
