package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
	initRoutingConfig(t)
	ws := &WebhookServer{Routers: routers}
	if err := ws.ReloadRouters(); err != nil {
		t.Fatalf("ReloadRouters: %v", err)
	}
	saved := GlobalWebhookServer
	GlobalWebhookServer = ws
	srv := httptest.NewServer(http.HandlerFunc(handleWebhooksV4))
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
