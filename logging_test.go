package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spirilis/spitter/alerts"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog runs the test at the given log level and returns what gets logged
func captureLog(t *testing.T, level string) *lockedBuffer {
	t.Helper()
	saved := currentLogLevel.Load()
	if err := setLogLevel(level); err != nil {
		t.Fatal(err)
	}
	buf := &lockedBuffer{}
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		currentLogLevel.Store(saved)
	})
	return buf
}

func TestSetLogLevel(t *testing.T) {
	saved := currentLogLevel.Load()
	t.Cleanup(func() { currentLogLevel.Store(saved) })

	for name, want := range map[string]logLevel{"trace": logLevelTrace, "debug": logLevelDebug, "INFO": logLevelInfo, "warning": logLevelWarning, " warn ": logLevelWarning} {
		if err := setLogLevel(name); err != nil {
			t.Errorf("setLogLevel(%q) error: %v", name, err)
		}
		if got := logLevel(currentLogLevel.Load()); got != want {
			t.Errorf("setLogLevel(%q) selected level %d, want %d", name, got, want)
		}
	}
	if err := setLogLevel("verbose"); err == nil {
		t.Errorf("setLogLevel(\"verbose\") succeeded, want an error")
	}

	setLogLevel("info")
	for level, want := range map[logLevel]bool{logLevelTrace: false, logLevelDebug: false, logLevelInfo: true, logLevelWarning: true} {
		if got := logEnabled(level); got != want {
			t.Errorf("at info, logEnabled(%d) = %v, want %v", level, got, want)
		}
	}
}

// What a webhook carries and what a template can read must stay out of the log unless trace is selected
func TestSecretsOnlyLoggedAtTrace(t *testing.T) {
	initRoutingConfig(t)
	t.Setenv("SPITTER_TEST_SECRET", "env-secret-value")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer srv.Close()

	send := func(t *testing.T, template string) {
		t.Helper()
		r := &WebhookRouter{DestURL: srv.URL, Template: template, Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}}}
		if err := r.Check(); err != nil {
			t.Fatal(err)
		}
		if err := r.prepare(); err != nil {
			t.Fatal(err)
		}
		in := &alerts.AlertmanagerWebhookInputV4{
			Version:      "4",
			CommonLabels: map[string]string{"severity": "critical"},
			Alerts:       []*alerts.AlertmanagerAlertV4{{Labels: map[string]string{}, Annotations: map[string]string{"summary": "annotation-text"}}},
		}
		data, err := r.PrepareTemplateData(in)
		if err != nil {
			t.Fatal(err)
		}
		r.SendWebhook(data)
	}
	rendered := `{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}`
	failing := `{{ .NoSuchField }}`

	t.Run("info", func(t *testing.T) {
		logs := captureLog(t, "info")
		send(t, rendered)
		send(t, failing)
		for _, secret := range []string{"env-secret-value", "annotation-text"} {
			if strings.Contains(logs.String(), secret) {
				t.Errorf("log at info contains %q", secret)
			}
		}
		if !strings.Contains(logs.String(), "failed to execute template") {
			t.Errorf("log at info does not report the template failure:\n%s", logs.String())
		}
	})
	t.Run("trace", func(t *testing.T) {
		logs := captureLog(t, "trace")
		send(t, rendered)
		send(t, failing)
		for _, want := range []string{"env-secret-value", "annotation-text"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("log at trace does not contain %q", want)
			}
		}
	})
}
