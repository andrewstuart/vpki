package vtls

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	day  = 24 * time.Hour
	year = 365 * day

	certTime = time.Minute
)

// ListenAndServeTLS mostly mirrors the http.ListenAndServeTLS API, but
// generates the certificates for the server automatically via vault, with a
// short TTL. The function only needs an additional Certifier parameter which
// can generate signed certificates in order to work properly.
func ListenAndServeTLS(addr string, handler http.Handler, crt Certifier) error {
	certs := map[string]*tls.Certificate{}
	certsM := &sync.RWMutex{}

	addCert := func(name string) (*tls.Certificate, error) {
		log.Println("Generating cert for ", name)
		crt, err := crt.Certify(name, certTime)
		if err != nil {
			return nil, err
		}

		certsM.Lock()
		certs[name] = &crt
		certsM.Unlock()
		return &crt, nil
	}

	getCert := func(name string) (*tls.Certificate, error) {
		lkr := certsM.RLocker()
		lkr.Lock()

		if c, ok := certs[name]; ok {
			log.Println(c.Leaf.NotAfter.String())
			n := time.Now()
			if n.After(c.Leaf.NotBefore) && n.Before(c.Leaf.NotAfter) {
				lkr.Unlock()
				return c, nil
			}
		}
		lkr.Unlock()

		return addCert(name)
	}

	tl, err := tls.Listen("tcp", addr, &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName == "" {
				return nil, fmt.Errorf("Cannot generate certs for IP alone")
			}
			return getCert(h.ServerName)
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
