package remotewrite

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/umatare5/xflow-exporter/internal/config"
)

// TestWriter_AuthorizationHeaderIsUnchanged pins the header a write carries
// for every way a credential can be configured. The endpoint URL may hold one
// and so may the configuration, and net/http applies the URL's only where the
// request carries no header yet -- so the transport's own beats it.
func TestWriter_AuthorizationHeaderIsUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		userinfo     string
		username     string
		password     string
		wantUser     string
		wantPassword string
		wantAuth     bool
	}{
		{"neither", "", "", "", "", "", false},
		{"the configuration alone", "", "carol", "cfgpass", "carol", "cfgpass", true},
		{"the URL alone", "alice:urlpass@", "", "", "alice", "urlpass", true},
		{"both, the configuration winning", "alice:urlpass@", "carol", "cfgpass", "carol", "cfgpass", true},
		{"a URL username with no password", "alice@", "", "", "alice", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seen := make(chan *http.Request, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Clone(context.Background())
				// The client reads its own statistics back, and a write it
				// reads as refused would retry past the one request pinned here.
				w.Header().Set("X-Prometheus-Remote-Write-Samples-Written", "2")
				w.Header().Set("X-Prometheus-Remote-Write-Histograms-Written", "0")
				w.Header().Set("X-Prometheus-Remote-Write-Exemplars-Written", "0")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			endpoint := "http://" + tt.userinfo + strings.TrimPrefix(srv.URL, "http://") + writePath
			w, err := New(config.RemoteWrite{
				URL:      endpoint,
				Username: tt.username,
				Password: tt.password,
				Interval: time.Minute,
				Timeout:  5 * time.Second,
			}, testRegistry(t))
			if err != nil {
				t.Fatalf("New() error = %v, want nil", err)
			}
			if err := w.send(context.Background()); err != nil {
				t.Fatalf("send() error = %v, want nil", err)
			}

			got := <-seen
			user, password, ok := got.BasicAuth()
			if ok != tt.wantAuth {
				t.Fatalf("BasicAuth() present = %v, want %v", ok, tt.wantAuth)
			}
			if user != tt.wantUser || password != tt.wantPassword {
				t.Errorf("BasicAuth() = %q/%q, want %q/%q", user, password, tt.wantUser, tt.wantPassword)
			}
		})
	}
}

// TestWriter_KeepsTheCredentialOutOfEveryLogLine drives a real send against a
// port nothing listens on, which is the path that repeats an endpoint on
// every interval it stays unreachable.
//
// It is not parallel: the client logs through the default logger, which this
// has to hold to read what a send writes.
//
//nolint:paralleltest // Holds the default logger, which a parallel test would race.
func TestWriter_KeepsTheCredentialOutOfEveryLogLine(t *testing.T) {
	const (
		user   = "alice"
		secret = "s3cr3t"
	)

	// A listener opened and closed hands back an address nothing answers on.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a closed port: %v", err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()

	var log bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	defer slog.SetDefault(restore)

	w, err := New(config.RemoteWrite{
		URL:      "http://" + user + ":" + secret + "@" + closed + writePath,
		Interval: time.Minute,
		Timeout:  time.Second,
	}, testRegistry(t))
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	// The client retries with backoff, so the context is what ends the send.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.send(ctx); err == nil {
		t.Fatal("send() error = nil against a closed port, want a failure")
	} else {
		slog.Error("Failed to ship metrics to the remote endpoint", "error", withoutURL(err))
	}

	written := log.String()
	if strings.Contains(written, secret) {
		t.Errorf("the log carries the password: %s", written)
	}
	if strings.Contains(written, user) {
		t.Errorf("the log carries the username: %s", written)
	}
	if !strings.Contains(written, closed) {
		t.Errorf("the log names no endpoint at all, want the host kept: %s", written)
	}
}

// TestSplitEndpoint_KeepsTheCredentialOutOfAParseFailure pins the one error
// the helper still reaches. A url.Error repeats the string it failed on, and
// a URL that does not parse cannot have its parts separated.
func TestSplitEndpoint_KeepsTheCredentialOutOfAParseFailure(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t"
	_, _, _, err := splitEndpoint("://alice:" + secret + "@example.test/write")
	if err == nil {
		t.Fatal("splitEndpoint() error = nil for a malformed URL, want it refused")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("splitEndpoint() error = %q, want the credential redacted", err)
	}
}
