package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spirilis/spitter/alerts"
)

// A mistake in a router must reject it when it is loaded, not surface (or stay hidden) when an alert arrives
func TestRouterCheckRejectsMistakes(t *testing.T) {
	valid := func() *WebhookRouter {
		return &WebhookRouter{
			DestURL:  "https://receiver.example.com/hook",
			Template: "{{ .Status }}",
			Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}},
		}
	}
	tests := []struct {
		name    string
		change  func(r *WebhookRouter)
		wantErr string // "" for a router that must be accepted
	}{
		{"valid", func(r *WebhookRouter) {}, ""},
		{"valid method", func(r *WebhookRouter) { r.HttpMethod = "PUT" }, ""},
		{"token", func(r *WebhookRouter) { r.Authentication = &WebhookAuthentication{BearerToken: "t"} }, ""},
		{"basic auth with an empty password", func(r *WebhookRouter) {
			r.Authentication = &WebhookAuthentication{BasicAuth: WebhookBasicAuth{Username: "u"}}
		}, ""},
		{"match and match_re together", func(r *WebhookRouter) { r.Matchers[0].MatchRegexp = "crit.*" }, ""},

		{"template with a syntax error", func(r *WebhookRouter) { r.Template = "{{ .Status " }, "template"},
		{"template calling an unknown function", func(r *WebhookRouter) { r.Template = "{{ nosuchfunc .Status }}" }, "template"},
		{"URL without a scheme", func(r *WebhookRouter) { r.DestURL = "receiver.example.com/hook" }, "URL"},
		{"URL with another scheme", func(r *WebhookRouter) { r.DestURL = "ftp://receiver.example.com/hook" }, "URL"},
		{"URL without a host", func(r *WebhookRouter) { r.DestURL = "https:///hook" }, "URL"},
		{"URL that does not parse", func(r *WebhookRouter) { r.DestURL = "https://[::1/hook" }, "URL"},
		{"invalid method", func(r *WebhookRouter) { r.HttpMethod = "PO ST" }, "method"},
		{"matcher without a label", func(r *WebhookRouter) { r.Matchers[0].Label = "" }, "label"},
		{"matcher with neither match nor match_re", func(r *WebhookRouter) { r.Matchers[0].MatchString = "" }, "neither"},
		{"token and basic auth", func(r *WebhookRouter) {
			r.Authentication = &WebhookAuthentication{BearerToken: "t", BasicAuth: WebhookBasicAuth{Username: "u", Password: "p"}}
		}, "more than one"},
		{"token and token file", func(r *WebhookRouter) {
			r.Authentication = &WebhookAuthentication{BearerToken: "t", BearerTokenFromFile: "/some/file"}
		}, "more than one"},
		{"basic auth password without a username", func(r *WebhookRouter) {
			r.Authentication = &WebhookAuthentication{BasicAuth: WebhookBasicAuth{Password: "p"}}
		}, "username"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.change(r)
			err := r.Check()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Check() error = %v, want the router accepted", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("Check() accepted the router, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("Check() error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestBasicAuthWithEmptyPasswordIsSent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { got = req.Header.Get("Authorization") }))
	defer srv.Close()
	r := newTestRouter(t, srv.URL, &WebhookAuthentication{BasicAuth: WebhookBasicAuth{Username: "alice"}}, nil)
	if err := r.SendWebhook(testAlert); err != nil {
		t.Fatal(err)
	}
	if want := "Basic YWxpY2U6"; got != want { // base64("alice:")
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

// One router with a broken template used to panic the handler: routers before it got a copy on every Alertmanager retry
// and routers after it got nothing.
func TestBrokenTemplateDoesNotAffectOtherRouters(t *testing.T) {
	logs := captureLog(t, "warning")
	first, bad, third := newDestination(t), newDestination(t), newDestination(t)
	spitter := startSpitter(t,
		criticalRouter(first.URL, "first"),
		criticalRouter(bad.URL, "{{ .Status "),
		criticalRouter(third.URL, "third"),
	)
	if got := len(GlobalWebhookServer.GetRouters()); got != 2 || routersRejected != 1 {
		t.Fatalf("loaded %d routers and rejected %d, want 2 and 1", got, routersRejected)
	}
	if !strings.Contains(logs.String(), "template does not parse") {
		t.Errorf("the rejection is not reported at warning level:\n%s", logs.String())
	}

	payload := `{"version":"4","status":"firing","commonLabels":{"severity":"critical"},"commonAnnotations":{},"alerts":[{"status":"firing","labels":{},"annotations":{}}]}`
	if status := post(t, spitter, payload); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(first.received()) != 1 || len(bad.received()) != 0 || len(third.received()) != 1 {
		t.Errorf("destinations received first=%d bad=%d third=%d webhooks, want 1, 0 and 1",
			len(first.received()), len(bad.received()), len(third.received()))
	}
}

// Should a router panic anyway, the routers after it still get the alert and Alertmanager still gets an answer
func TestHandlerIsolatesRouterPanic(t *testing.T) {
	logs := captureLog(t, "warning")
	after := newDestination(t)
	spitter := startSpitter(t, criticalRouter(after.URL, "after"))

	good := GlobalWebhookServer.GetRouters()[0]
	// Authentication is nil only on a router that skipped Check, which makes SendWebhook dereference a nil pointer
	broken := &WebhookRouter{DestURL: "http://127.0.0.1:1/never", Template: "x", Matchers: good.Matchers, tmpl: good.tmpl, client: good.client}
	GlobalWebhookServer.allRouters = []*WebhookRouter{broken, good}

	payload := `{"version":"4","status":"firing","commonLabels":{"severity":"critical"},"commonAnnotations":{},"alerts":[{"status":"firing","labels":{},"annotations":{}}]}`
	if status := post(t, spitter, payload); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := after.received(); len(got) != 1 {
		t.Errorf("the router after the panicking one received %d webhooks, want 1", len(got))
	}
	if !strings.Contains(logs.String(), "panicked") {
		t.Errorf("the panic is not reported at warning level:\n%s", logs.String())
	}
}

func TestRouterDirectoryLoading(t *testing.T) {
	logs := captureLog(t, "warning")
	const good = "url: https://receiver.example.com/hook\ntemplate: x\nmatchers:\n- {label: severity, match: critical}\n"
	write := func(t *testing.T, dir, name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("mistakes are rejected and counted", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "good.yml", good)
		// With the keys misspelled, this router would have been sent without its token and with default TLS settings
		write(t, dir, "misspelled-auth.yml", good+"auht: {token: abc}\n")
		write(t, dir, "misspelled-tls.yml", good+"tsl: {caFile: /etc/ca.pem}\n")
		write(t, dir, "duplicate-key.yml", good+"url: https://other.example.com/hook\n")
		write(t, dir, "not-yaml.yml", "url: [unterminated\n")
		write(t, dir, "empty.yml", "")

		w := &WebhookServer{AdditionalRouterDirectory: dir}
		if err := w.ReloadRouters(); err != nil {
			t.Fatal(err)
		}
		if got := len(w.GetRouters()); got != 1 || routersRejected != 5 {
			t.Errorf("loaded %d routers and rejected %d, want 1 and 5", got, routersRejected)
		}
		for _, name := range []string{"misspelled-auth.yml", "misspelled-tls.yml", "duplicate-key.yml", "not-yaml.yml", "empty.yml"} {
			if !strings.Contains(logs.String(), name) {
				t.Errorf("the rejection of %s is not reported at warning level", name)
			}
		}
	})

	// A ConfigMap or Secret volume: the files are links into a "..data" directory link, next to a timestamped directory
	t.Run("a ConfigMap volume's own entries are not counted as rejected", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "..2026_11_25"), 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, "..2026_11_25"), "router.yml", good)
		if err := os.Symlink("..2026_11_25", filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", "router.yml"), filepath.Join(dir, "router.yml")); err != nil {
			t.Fatal(err)
		}

		w := &WebhookServer{AdditionalRouterDirectory: dir}
		if err := w.ReloadRouters(); err != nil {
			t.Fatal(err)
		}
		if got := len(w.GetRouters()); got != 1 || routersRejected != 0 {
			t.Errorf("loaded %d routers and rejected %d, want 1 and 0", got, routersRejected)
		}
	})
}

func TestConfigFileIsDecodedStrictly(t *testing.T) {
	dir := t.TempDir()
	const good = "alertmanagerURL: http://alertmanager\nprometheusURL: http://prometheus\nlogLevel: info\nlisten: {port: 9820}\nmetrics: {path: /metrics}\n" +
		"routers:\n- url: https://receiver.example.com/hook\n  template: x\n  auth: {token: abc}\n  matchers:\n  - {label: severity, match: critical}\n"

	path := filepath.Join(dir, "good.yml")
	os.WriteFile(path, []byte(good), 0o600)
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("loadConfigFile error: %v", err)
	}
	if cfg.LogLevel != "info" || len(cfg.Routers) != 1 || cfg.Routers[0].Authentication.BearerToken != "abc" {
		t.Errorf("config was not decoded as written: %#v", cfg)
	}

	for name, contents := range map[string]string{
		"misspelled top-level key": strings.Replace(good, "alertmanagerURL", "alertmangerURL", 1),
		"misspelled router key":    strings.Replace(good, "auth:", "auht:", 1),
		"misspelled matcher key":   strings.Replace(good, "match:", "matches:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "bad.yml")
			os.WriteFile(path, []byte(contents), 0o600)
			if _, err := loadConfigFile(path); err == nil {
				t.Errorf("loadConfigFile accepted the config, want an error")
			}
		})
	}
}

// A reload must not touch routers that requests are using, nor the configuration they were built from
func TestReloadBuildsNewRouters(t *testing.T) {
	captureLog(t, "warning")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	defer srv.Close()

	configured := &WebhookRouter{
		DestURL:  srv.URL,
		Template: "x",
		Matchers: []*WebhookMatcher{{Label: "severity", MatchRegexp: "crit.*"}},
	}
	withToken := &WebhookRouter{
		DestURL:        srv.URL,
		Template:       "x",
		Authentication: &WebhookAuthentication{BearerTokenFromFile: tokenFile, Cookies: map[string]string{"a": "b"}},
		Matchers:       []*WebhookMatcher{{Label: "severity", MatchString: "critical"}},
	}
	ws := &WebhookServer{Routers: []*WebhookRouter{configured, withToken}}
	if err := ws.ReloadRouters(); err != nil {
		t.Fatal(err)
	}
	firstLoad := ws.GetRouters()
	if err := ws.ReloadRouters(); err != nil {
		t.Fatal(err)
	}
	secondLoad := ws.GetRouters()

	for i := range ws.Routers {
		if firstLoad[i] == ws.Routers[i] || secondLoad[i] == ws.Routers[i] || firstLoad[i] == secondLoad[i] {
			t.Errorf("router %d: a reload reused a router object instead of building a new one", i)
		}
		if firstLoad[i].Matchers[0] == ws.Routers[i].Matchers[0] {
			t.Errorf("router %d: loaded router shares its matchers with the configuration", i)
		}
	}
	if firstLoad[1].Authentication == withToken.Authentication {
		t.Errorf("loaded router shares its auth settings with the configuration")
	}
	// Loading fills in defaults and compiled state; none of it may land on the configuration
	if configured.HttpMethod != "" || configured.ContentType != "" || configured.Authentication != nil ||
		configured.tmpl != nil || configured.client != nil || configured.Matchers[0].compiledRegexp != nil {
		t.Errorf("reload changed the configured router: %#v", configured)
	}
	if firstLoad[0].HttpMethod != "POST" || firstLoad[0].tmpl == nil || firstLoad[0].client == nil {
		t.Errorf("loaded router is missing its defaults: %#v", firstLoad[0])
	}

	// Under -race: reloads while webhooks are being sent
	in := &alerts.AlertmanagerWebhookInputV4{
		Version:      "4",
		CommonLabels: map[string]string{"severity": "critical"},
		Alerts:       []*alerts.AlertmanagerAlertV4{{Status: "firing"}},
	}
	var wg sync.WaitGroup
	for range 3 { // SIGHUP, the trigger file and the directory watcher can each start one
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if err := ws.ReloadRouters(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for range 50 {
		for _, r := range ws.GetRouters() {
			routeWebhook(r, in)
		}
	}
	wg.Wait()
}

func TestTokenFileIsReadForEverySend(t *testing.T) {
	logs := captureLog(t, "warning")
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeToken := func(token string) {
		t.Helper()
		if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got = append(got, req.Header.Get("Authorization"))
	}))
	defer srv.Close()

	writeToken("first\n")
	r := newTestRouter(t, srv.URL, &WebhookAuthentication{BearerTokenFromFile: tokenFile}, nil)
	if err := r.SendWebhook(testAlert); err != nil {
		t.Fatal(err)
	}
	// The token is rotated on disk; no reload happens
	writeToken("second\n")
	if err := r.SendWebhook(testAlert); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "Bearer first,Bearer second" {
		t.Errorf("destination saw Authorization headers %q, want [Bearer first, Bearer second]", got)
	}

	// Sending without credentials would only earn a 401, or worse, be accepted
	for name, breakIt := range map[string]func(){
		"missing": func() { os.Remove(tokenFile) },
		"empty":   func() { writeToken("\n") },
	} {
		breakIt()
		if err := r.SendWebhook(testAlert); err == nil {
			t.Errorf("SendWebhook with a %s token file succeeded, want an error", name)
		}
	}
	if len(got) != 2 {
		t.Errorf("destination received %d webhooks, want 2: none may be sent without the token", len(got))
	}
	if !strings.Contains(logs.String(), "no credentials") {
		t.Errorf("the failure is not reported at warning level:\n%s", logs.String())
	}

	// And a router whose token file is unusable when it is loaded is rejected, as before
	unprepared := &WebhookRouter{DestURL: srv.URL, Template: "x", Matchers: []*WebhookMatcher{{Label: "a", MatchString: "b"}},
		Authentication: &WebhookAuthentication{BearerTokenFromFile: tokenFile}}
	if err := unprepared.Check(); err != nil {
		t.Fatal(err)
	}
	if err := unprepared.prepare(); err == nil {
		t.Errorf("prepare() accepted a router with an empty token file")
	}
}
