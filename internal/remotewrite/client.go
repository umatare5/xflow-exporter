// This file builds the HTTP client the writes travel on.

package remotewrite

import (
	"net/http"
	"net/url"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// authTransport adds the configured credentials to every request.
type authTransport struct {
	base     http.RoundTripper
	username string
	password string
	// authorize carries whether a credential was configured at all, which an
	// empty username cannot: a URL may hold a password against one.
	authorize bool
	headers   map[string]string
}

// RoundTrip implements http.RoundTripper.
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The request is cloned before it is touched: RoundTrip must not modify
	// the one it was handed.
	clone := req.Clone(req.Context())

	for name, value := range t.headers {
		clone.Header.Set(name, value)
	}
	if t.authorize {
		clone.SetBasicAuth(t.username, t.password)
	}

	return t.base.RoundTrip(clone)
}

// newHTTPClient builds the client the writes travel on.
func newHTTPClient(cfg config.RemoteWrite, credential *url.Userinfo) *http.Client {
	// A credential the endpoint URL carried applies only where the
	// configuration names none, which is the order that held while the URL
	// still reached the request: net/http fills the header from the URL, and
	// this transport overwrites it.
	username, password, authorize := cfg.Username, cfg.Password, cfg.Username != ""
	if !authorize && credential != nil {
		username = credential.Username()
		password, _ = credential.Password()
		authorize = true
	}

	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &authTransport{
			base:      http.DefaultTransport,
			username:  username,
			password:  password,
			authorize: authorize,
			headers:   cfg.Headers,
		},
	}
}
