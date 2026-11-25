package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// destination records the webhooks spitter sends to it
type destination struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newDestination(t *testing.T) *destination {
	t.Helper()
	d := &destination{}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		d.mu.Lock()
		d.bodies = append(d.bodies, string(b))
		d.mu.Unlock()
	}))
	t.Cleanup(d.Close)
	return d
}

func (d *destination) received() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.bodies...)
}

// startSpitter serves handleWebhooksV4 with the given routers, loaded the way Start loads them
func startSpitter(t *testing.T, routers ...*WebhookRouter) *httptest.Server {
	t.Helper()
	return startSpitterWith(t, &WebhookServer{Routers: routers})
}

// startSpitterWith does the same for a whole server config, behind the http.Server that Start would use
func startSpitterWith(t *testing.T, ws *WebhookServer) *httptest.Server {
	t.Helper()
	initRoutingConfig(t)
	if err := ws.ReloadRouters(); err != nil {
		t.Fatalf("ReloadRouters: %v", err)
	}
	saved := GlobalWebhookServer
	GlobalWebhookServer = ws
	srv := httptest.NewUnstartedServer(http.HandlerFunc(handleWebhooksV4))
	configured := ws.httpServer()
	srv.Config.ReadHeaderTimeout = configured.ReadHeaderTimeout
	srv.Config.ReadTimeout = configured.ReadTimeout
	srv.Config.IdleTimeout = configured.IdleTimeout
	srv.Start()
	t.Cleanup(func() {
		srv.Close()
		GlobalWebhookServer = saved
	})
	return srv
}

// post sends a payload the way Alertmanager does and returns the status spitter answered with
func post(t *testing.T, spitter *httptest.Server, payload string) int {
	t.Helper()
	resp, err := http.Post(spitter.URL, "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("posting webhook: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func criticalRouter(url, template string) *WebhookRouter {
	return &WebhookRouter{DestURL: url, Template: template, Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}}}
}

func TestHandlerRoutesNativePayload(t *testing.T) {
	captureLog(t, "warning")
	dest := newDestination(t)
	spitter := startSpitter(t, criticalRouter(dest.URL,
		`{{ .Status }}|{{ .NotificationReason }}|{{ .TruncatedAlertCount }}|{{ .GroupKey }}|{{ .RouteLabels.team }}|`+
			`{{ range .Alerts }}{{ .Status }},{{ .Labels.alertname }},{{ .Labels.severity }},{{ .Annotations.summary }},{{ .StartsAt }},{{ .EndsAt }},{{ .OriginalGeneratorURL }},{{ .Fingerprint }}{{ end }}`))

	status := post(t, spitter, `{
	  "version": "4", "groupKey": "gk", "truncatedAlerts": 3, "status": "firing", "receiver": "spitter",
	  "groupLabels": {"alertname": "Disk"}, "commonLabels": {"alertname": "Disk", "severity": "critical"}, "commonAnnotations": {},
	  "routeLabels": {"team": "platform"}, "externalURL": "http://alertmanager:9093", "notification_reason": "first notification",
	  "alerts": [{"status": "firing", "labels": {"alertname": "Disk", "severity": "critical"}, "annotations": {"summary": "full"},
	    "startsAt": "2026-11-25T10:00:00Z", "endsAt": "0001-01-01T00:00:00Z", "generatorURL": "http://prometheus:9090/graph", "fingerprint": "abc123"}]
	}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	want := "firing|first notification|3|gk|platform|firing,Disk,critical,full,2026-11-25T10:00:00Z,0001-01-01T00:00:00Z,http://prometheus:9090/graph,abc123"
	if got := dest.received(); len(got) != 1 || got[0] != want {
		t.Errorf("destination received %q, want [%q]", got, want)
	}
}

// Alertmanager encodes with encoding/json, which leaves these characters as they are.  A YAML decoder refuses or alters them.
func TestHandlerAcceptsEverythingJSONCanCarry(t *testing.T) {
	captureLog(t, "warning")
	for name, text := range map[string]string{
		"DEL":        "bad\x7fbyte",
		"C1 control": "ansi \u009b31m",
		"U+FFFE":     "x￾y",
		"NEL":        "line\u0085break",
		"markup":     `a < b && "c" > d`,
	} {
		t.Run(name, func(t *testing.T) {
			dest := newDestination(t)
			spitter := startSpitter(t, criticalRouter(dest.URL, `{{ range .Alerts }}{{ .Annotations.description }}{{ end }}`))
			payload, err := json.Marshal(map[string]any{
				"version": "4", "status": "firing", "commonLabels": map[string]string{"severity": "critical"}, "commonAnnotations": map[string]string{},
				"alerts": []any{map[string]any{"status": "firing", "labels": map[string]string{"severity": "critical"}, "annotations": map[string]string{"description": text}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if status := post(t, spitter, string(payload)); status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if got := dest.received(); len(got) != 1 || got[0] != text {
				t.Errorf("destination received %q, want [%q]", got, text)
			}
		})
	}
}

// Nothing can be routed from these, so Alertmanager must not be told the notification was delivered
func TestHandlerRefusesUnusablePayloads(t *testing.T) {
	logs := captureLog(t, "warning")
	dest := newDestination(t)
	spitter := startSpitter(t, criticalRouter(dest.URL, "x"))

	for name, payload := range map[string]string{
		"version 5":        `{"version":"5","commonLabels":{"severity":"critical"},"alerts":[{"labels":{},"annotations":{}}]}`,
		"no version":       `{"commonLabels":{"severity":"critical"},"alerts":[{"labels":{},"annotations":{}}]}`,
		"yaml":             "version: \"4\"\ncommonLabels: {severity: critical}\n",
		"not an object":    `["version", "4"]`,
		"truncated":        `{"version":"4","commonLabels":{"severity":"crit`,
		"trailing garbage": `{"version":"4","commonLabels":{"severity":"critical"},"alerts":[]} extra`,
	} {
		t.Run(name, func(t *testing.T) {
			if status := post(t, spitter, payload); status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", status)
			}
		})
	}
	if got := dest.received(); len(got) != 0 {
		t.Errorf("destination received %d webhooks, want none", len(got))
	}
	if !strings.Contains(logs.String(), "version") {
		t.Errorf("refused payloads are not reported at warning level:\n%s", logs.String())
	}
}

// A hand-made or broken payload must not take the handler down
func TestHandlerSurvivesMalformedAlerts(t *testing.T) {
	captureLog(t, "warning")
	for name, alertList := range map[string]string{
		"null alert":         `[null, {"status":"firing","labels":{"alertname":"A"},"annotations":{}}]`,
		"labels missing":     `[{"status":"firing"}]`,
		"labels null":        `[{"status":"firing","labels":null,"annotations":null}]`,
		"no alerts":          `[]`,
		"alerts null":        `null`,
		"only a null alert":  `[null]`,
		"annotations absent": `[{"status":"firing","labels":{"alertname":"A"}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			dest := newDestination(t)
			spitter := startSpitter(t, criticalRouter(dest.URL, `{{ range .Alerts }}{{ .Labels.severity }}/{{ .Annotations.runbook }};{{ end }}`))
			payload := `{"version":"4","status":"firing","commonLabels":{"severity":"critical"},"commonAnnotations":{"runbook":"rb"},"alerts":` + alertList + `}`
			if status := post(t, spitter, payload); status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if got := dest.received(); len(got) != 1 {
				t.Fatalf("destination received %d webhooks, want 1", len(got))
			}
		})
	}
}

func TestHandlerMatchesWholeAlerts(t *testing.T) {
	captureLog(t, "warning")
	twoMatchers := func(url string) *WebhookRouter {
		return &WebhookRouter{DestURL: url,
			Template: `{{ .Status }}:{{ range .Alerts }}{{ .Labels.alertname }}={{ .Status }};{{ end }}`,
			Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}, {Label: "team", MatchString: "db"}}}
	}
	alert := func(name, status, severity, team string) string {
		return `{"status":"` + status + `","labels":{"alertname":"` + name + `","severity":"` + severity + `","team":"` + team + `"},"annotations":{}}`
	}
	group := func(status string, alertList ...string) string {
		return `{"version":"4","status":"` + status + `","commonLabels":{},"commonAnnotations":{},"alerts":[` + strings.Join(alertList, ",") + `]}`
	}

	tests := []struct {
		name    string
		payload string
		want    []string
	}{
		{
			// severity=critical is on A and team=db is on B: every matcher finds something, but no alert is wanted
			name:    "matchers satisfied by different alerts send nothing",
			payload: group("firing", alert("A", "firing", "critical", "web"), alert("B", "firing", "info", "db")),
			want:    nil,
		},
		{
			name:    "status describes the alerts that are sent",
			payload: group("firing", alert("A", "resolved", "critical", "db"), alert("B", "firing", "info", "web")),
			want:    []string{"resolved:A=resolved;"},
		},
		{
			name:    "one firing alert among those sent keeps the group firing",
			payload: group("firing", alert("A", "resolved", "critical", "db"), alert("B", "firing", "critical", "db"), alert("C", "firing", "info", "web")),
			want:    []string{"firing:A=resolved;B=firing;"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := newDestination(t)
			spitter := startSpitter(t, twoMatchers(dest.URL))
			attemptedBefore := counterValue(t, webhookreqAttemptedCounter)
			if status := post(t, spitter, tc.payload); status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			got := dest.received()
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("destination received %q, want %q", got, tc.want)
			}
			if attempted := counterValue(t, webhookreqAttemptedCounter) - attemptedBefore; attempted != float64(len(tc.want)) {
				t.Errorf("attempted counter rose by %v, want %d", attempted, len(tc.want))
			}
		})
	}
}

func alertPayload(summary string) string {
	payload, _ := json.Marshal(map[string]any{
		"version": "4", "status": "firing", "commonLabels": map[string]string{"severity": "critical"}, "commonAnnotations": map[string]string{},
		"alerts": []any{map[string]any{"status": "firing", "labels": map[string]string{}, "annotations": map[string]string{"summary": summary}}},
	})
	return string(payload)
}

// Nothing bounded what a caller could make spitter hold in memory
func TestHandlerRefusesOversizedBody(t *testing.T) {
	logs := captureLog(t, "warning")
	dest := newDestination(t)
	spitter := startSpitterWith(t, &WebhookServer{
		Listen:  &WebhookServerListen{MaxBodyBytes: 4096},
		Routers: []*WebhookRouter{criticalRouter(dest.URL, "x")},
	})

	if status := post(t, spitter, alertPayload(strings.Repeat("A", 8192))); status != http.StatusRequestEntityTooLarge {
		t.Errorf("status for a body over the limit = %d, want 413", status)
	}
	if got := dest.received(); len(got) != 0 {
		t.Errorf("destination received %d webhooks from the oversized body, want none", len(got))
	}
	if !strings.Contains(logs.String(), "maxBodyBytes") {
		t.Errorf("the refusal is not reported at warning level:\n%s", logs.String())
	}

	if status := post(t, spitter, alertPayload(strings.Repeat("A", 2048))); status != http.StatusOK {
		t.Errorf("status for a body under the limit = %d, want 200", status)
	}
	if got := dest.received(); len(got) != 1 {
		t.Errorf("destination received %d webhooks, want 1", len(got))
	}
}

func TestServerLimits(t *testing.T) {
	tests := []struct {
		name     string
		listen   *WebhookServerListen
		wantBody int64
		wantIdle time.Duration
	}{
		{"defaults without a listen section", nil, 10 << 20, 10 * time.Minute},
		{"defaults", &WebhookServerListen{Port: 9820}, 10 << 20, 10 * time.Minute},
		{"configured", &WebhookServerListen{MaxBodyBytes: 1 << 20, IdleTimeout: time.Minute}, 1 << 20, time.Minute},
		// net/http reads a negative idle timeout as "none", and a zero one as "use the read timeout"
		{"idle timeout switched off", &WebhookServerListen{IdleTimeout: -1}, 10 << 20, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ws := &WebhookServer{Listen: tc.listen}
			if got := ws.maxBodyBytes(); got != tc.wantBody {
				t.Errorf("maxBodyBytes() = %d, want %d", got, tc.wantBody)
			}
			srv := ws.httpServer()
			if srv.IdleTimeout != tc.wantIdle {
				t.Errorf("IdleTimeout = %s, want %s", srv.IdleTimeout, tc.wantIdle)
			}
			if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 30*time.Second {
				t.Errorf("ReadHeaderTimeout = %s and ReadTimeout = %s, want 10s and 30s", srv.ReadHeaderTimeout, srv.ReadTimeout)
			}
			// The answer is written only after every router has been sent to, which can take minutes
			if srv.WriteTimeout != 0 {
				t.Errorf("WriteTimeout = %s, want none", srv.WriteTimeout)
			}
		})
	}
}

// The read timeout bounds how long a request may take to arrive.  It must not cut off a webhook whose routers are slow.
func TestSlowRouterOutlivesReadTimeout(t *testing.T) {
	captureLog(t, "warning")
	initRoutingConfig(t)
	const readTimeout = 100 * time.Millisecond
	var delivered atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(4 * readTimeout)
		delivered.Add(1)
	}))
	defer slow.Close()

	ws := &WebhookServer{Routers: []*WebhookRouter{criticalRouter(slow.URL, "x")}}
	if err := ws.ReloadRouters(); err != nil {
		t.Fatal(err)
	}
	saved := GlobalWebhookServer
	GlobalWebhookServer = ws
	t.Cleanup(func() { GlobalWebhookServer = saved })
	spitter := httptest.NewUnstartedServer(http.HandlerFunc(handleWebhooksV4))
	spitter.Config.ReadTimeout = readTimeout
	spitter.Config.ReadHeaderTimeout = readTimeout
	spitter.Start()
	defer spitter.Close()

	// Twice, so that a server left in a bad state by the first request would show
	client := spitter.Client()
	for attempt := 1; attempt <= 2; attempt++ {
		resp, err := client.Post(spitter.URL, "application/json", strings.NewReader(alertPayload("s")))
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("attempt %d: status = %d, want 200", attempt, resp.StatusCode)
		}
	}
	if got := delivered.Load(); got != 2 {
		t.Errorf("slow destination received %d webhooks, want 2", got)
	}
}

// Even at trace, one large request must not become an equally large log line
func TestTraceLogCapsTheBody(t *testing.T) {
	logs := captureLog(t, "trace")
	dest := newDestination(t)
	spitter := startSpitter(t, criticalRouter(dest.URL, "x"))
	if status := post(t, spitter, alertPayload(strings.Repeat("A", 512<<10))); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := len(logs.String()); got > 128<<10 {
		t.Errorf("a 512 kB request produced %d bytes of log, want the body capped at 64 kB", got)
	}
	if !strings.Contains(logs.String(), "truncated") {
		t.Errorf("the log does not say the body was truncated")
	}
}
