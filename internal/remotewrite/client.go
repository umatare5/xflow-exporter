// This file builds the HTTP client the writes travel on.

package remotewrite

import (
	"net/http"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// authTransport adds the configured credentials to every request.
type authTransport struct {
	base     http.RoundTripper
	username string
	password string
	headers  map[string]string
}

// RoundTrip implements http.RoundTripper.
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The request is cloned before it is touched: RoundTrip must not modify
	// the one it was handed.
	clone := req.Clone(req.Context())

	for name, value := range t.headers {
		clone.Header.Set(name, value)
	}
	if t.username != "" {
		clone.SetBasicAuth(t.username, t.password)
	}

	return t.base.RoundTrip(clone)
}

// newHTTPClient builds the client the writes travel on.
func newHTTPClient(cfg config.RemoteWrite) *http.Client {
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &authTransport{
			base:     http.DefaultTransport,
			username: cfg.Username,
			password: cfg.Password,
			headers:  cfg.Headers,
		},
	}
}
