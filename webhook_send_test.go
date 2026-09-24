package main

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spirilis/spitter/alerts"
)

func TestMain(m *testing.M) {
	// Start registers this counter, but SendWebhook is called here without starting a server
	webhookreqSuccessfulCounter = prometheus.NewCounter(prometheus.CounterOpts{Name: "test_webhook_requests_successful"})
	os.Exit(m.Run())
}

// newTestRouter returns a router for url that has been through the same Check and prepare as ReloadRouters.
func newTestRouter(t *testing.T, url string, auth *WebhookAuthentication, tlsConfig *WebhookTLS) *WebhookRouter {
	t.Helper()
	r := &WebhookRouter{
		DestURL:        url,
		Template:       "status: {{ .Status }}",
		Authentication: auth,
		TLS:            tlsConfig,
		Matchers:       []*WebhookMatcher{{Label: "severity", MatchRegexp: ".*"}},
	}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if err := r.prepare(); err != nil {
		t.Fatal(err)
	}
	return r
}

var testAlert = &alerts.AlertmanagerWebhookTemplateV4{Status: "firing"}

func TestSendWebhookAuthorization(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		auth *WebhookAuthentication
		want string
	}{
		{"none", nil, ""},
		{"bearer", &WebhookAuthentication{BearerToken: "s3cret"}, "Bearer s3cret"},
		{"bearer from file", &WebhookAuthentication{BearerTokenFromFile: tokenFile}, "Bearer file-token"},
		{"basic", &WebhookAuthentication{BasicAuth: WebhookBasicAuth{Username: "alice", Password: "p@ss:word"}}, "Basic YWxpY2U6cEBzczp3b3Jk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				got <- req.Header.Get("Authorization")
			}))
			defer srv.Close()

			if err := newTestRouter(t, srv.URL, tt.auth, nil).SendWebhook(testAlert); err != nil {
				t.Fatal(err)
			}
			if h := <-got; h != tt.want {
				t.Errorf("Authorization = %q, want %q", h, tt.want)
			}
		})
	}
}

// writeServerCA writes the httptest server's self-signed certificate to a PEM file usable as tls.caFile.
func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile
}

func TestSendWebhookTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer srv.Close()
	caFile := writeServerCA(t, srv)

	tests := []struct {
		name       string
		tls        *WebhookTLS
		wantVerify bool
	}{
		{"default", nil, true},
		{"empty tls block", &WebhookTLS{}, true},
		{"insecureSkipVerify", &WebhookTLS{InsecureSkipVerify: true}, false},
		{"caFile", &WebhookTLS{CAFile: caFile}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newTestRouter(t, srv.URL, nil, tt.tls).SendWebhook(testAlert)
			var verifyErr *tls.CertificateVerificationError
			switch {
			case tt.wantVerify && !errors.As(err, &verifyErr):
				t.Fatalf("expected a certificate verification error from the self-signed endpoint, got: %v", err)
			case !tt.wantVerify && err != nil:
				t.Fatal(err)
			}
		})
	}
}

func TestReloadRoutersTLSConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer srv.Close()
	caFile := writeServerCA(t, srv)
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	routers := map[string]string{
		"good.yml":       caFile,
		"missing-ca.yml": filepath.Join(dir, "missing.pem"),
		"not-pem.yml":    notPEM,
	}
	for name, ca := range routers {
		doc := fmt.Sprintf("url: %s\ntemplate: x\ntls:\n  caFile: %s\nmatchers:\n- label: severity\n  match_re: .*\n", srv.URL, ca)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	w := &WebhookServer{AdditionalRouterDirectory: dir}
	if err := w.ReloadRouters(); err != nil {
		t.Fatal(err)
	}
	loaded := w.GetRouters()
	if len(loaded) != 1 || routersRejected != 2 {
		t.Fatalf("got %d routers and %d rejected, want 1 and 2 (unreadable and non-PEM caFile)", len(loaded), routersRejected)
	}
	if loaded[0].TLS == nil || loaded[0].TLS.CAFile != caFile {
		t.Fatalf("tls.caFile was not decoded: %#v", loaded[0].TLS)
	}
	if err := loaded[0].SendWebhook(testAlert); err != nil {
		t.Fatal(err)
	}
}
